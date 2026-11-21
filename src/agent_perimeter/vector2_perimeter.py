"""Vector 2 (Secondary, Hardened): External Agentic Perimeter, DNS-AID, CT/TLS SAN & OAuth Hygiene.

Key Phase 1 hardening over Phase 0:
  - Multi-provider CT (CertSpotter primary + crt.sh circuit-breaker fallback) + live TLS SAN extraction
  - Open DNS standards: DNS-AID (_agent / _mcp SVCB/TXT/SRV) + DNSSEC AD validation
  - Drops legacy `agent.<domain>` monitoring/telemetry noise; focuses on `mcp.*` / `agents.*` / CT-discovered MCP hosts
  - Audits RFC 9728 (/.well-known/oauth-protected-resource + path-inserted /mcp + WWW-Authenticate resource_metadata)
  - Detects Broad OAuth Scope Declarations (wildcards, admin/write-all, excessive scope sprawl)
  - Detects Cross-Domain Perimeter Drift (sibling domain vs. unverified 3rd-party external delegation)
  - Follows endpoint pointers in /.well-known/mcp.json & agent.json to eliminate Phase 0 false positives
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse

from .dns_ct import (
    doh_resolve,
    host_matches_any,
    inspect_tls_cert,
    probe_dns_aid,
    query_ct_agent_subdomains,
    registrable_domain,
    url_host,
    url_matches_any,
)
from .http_client import HttpResponse, PoliteHttpClient, extract_html_title
from .models import BrandTarget, Evidence, Finding
from .taxonomy import FINDING_DEFINITIONS, owasp_list_for

WELL_KNOWN_PATHS = (
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/mcp.json",
    "/.well-known/mcp/server-card.json",
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
)

# High-privilege / overly broad OAuth scope indicators
BROAD_SCOPE_RE = re.compile(
    r"(^(\*|all|admin|root|superuser|full|full[_-]?access|write|read_write|readwrite)$"
    r"|[:._/](admin|write|delete|manage|all|\*|full|sudo|owner|billing)$"
    r"|^(org|account|workspace|project|wallet|repo|admin)[:._/](admin|write|delete|\*|all))",
    re.IGNORECASE,
)

RESOURCE_METADATA_HEADER_RE = re.compile(r'resource_metadata\s*=\s*"([^"]+)"', re.IGNORECASE)


def _parse_json_discovery(resp: HttpResponse) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    if resp.status != 200:
        return False, None, f"http_{resp.status}"
    body = resp.body_text.lstrip()
    if not body:
        return False, None, "empty_body"
    if body.lower().startswith(("<!doctype", "<html", "<head", "<body")):
        return False, None, "soft_404_html"
    try:
        parsed = json.loads(resp.body_text)
        if isinstance(parsed, dict):
            return True, parsed, "valid_json_object"
        return False, None, "json_not_object"
    except Exception:
        return False, None, "invalid_json"


def _extract_declared_endpoints(parsed: Dict[str, Any]) -> List[str]:
    """Extract target MCP/agent endpoint URLs declared inside /.well-known/mcp.json or agent.json."""
    urls: List[str] = []
    for k in ("endpoint", "url", "mcp_endpoint", "server_url"):
        v = parsed.get(k)
        if isinstance(v, str) and v.startswith(("http://", "https://")):
            urls.append(v)
    servers = parsed.get("mcpServers") or parsed.get("servers")
    if isinstance(servers, dict):
        for sv in servers.values():
            if isinstance(sv, dict):
                for k in ("url", "endpoint"):
                    v = sv.get(k)
                    if isinstance(v, str) and v.startswith(("http://", "https://")):
                        urls.append(v)
    elif isinstance(servers, list):
        for sv in servers:
            if isinstance(sv, dict):
                for k in ("url", "endpoint"):
                    v = sv.get(k)
                    if isinstance(v, str) and v.startswith(("http://", "https://")):
                        urls.append(v)
    return urls


def _analyze_scopes(scopes: List[str]) -> Tuple[List[str], bool]:
    """Identify overly broad/admin/wildcard OAuth scopes."""
    flagged: List[str] = []
    for sc in scopes:
        s = str(sc).strip()
        if not s:
            continue
        if BROAD_SCOPE_RE.search(s):
            flagged.append(s)
    is_broad = len(flagged) >= 2 or any(s in ("*", "admin", "full_access", "all") for s in flagged) or (
        len(flagged) >= 1 and len(scopes) >= 6
    ) or len(scopes) >= 15
    return flagged[:20], is_broad


def _fetch_rfc9728_from_url(client: PoliteHttpClient, metadata_url: str) -> Optional[Dict[str, Any]]:
    resp = client.get(metadata_url, timeout=5.5, max_bytes=131072, retries=0)
    ok, parsed, _ = _parse_json_discovery(resp)
    if ok and parsed:
        return {
            "url": resp.final_url,
            "resource": parsed.get("resource"),
            "authorization_servers": parsed.get("authorization_servers") or [],
            "scopes_supported": parsed.get("scopes_supported") or [],
            "bearer_methods_supported": parsed.get("bearer_methods_supported") or [],
        }
    return None


def _has_confirmed_mcp_signal(
    fqdn: str,
    r_root: HttpResponse,
    r_mcp: HttpResponse,
    host_rfc9728: Optional[Dict[str, Any]],
    host_cards: Dict[str, Any],
    header_metadata_url: Optional[str],
) -> bool:
    """Confirm whether a live subdomain is an active MCP/Agent endpoint rather than
    a legacy API gateway 400 error, React SPA HTML catch-all, or multi-tenant SSO portal.
    """
    if host_rfc9728 or host_cards or header_metadata_url:
        return True

    final_root_host = url_host(r_root.final_url)
    root_redirected_to_marketing = bool(
        final_root_host and final_root_host != fqdn.lower() and r_mcp.status in (0, 404)
    )
    if root_redirected_to_marketing:
        return False

    if not fqdn.lower().startswith("mcp."):
        return False

    mcp_body_low = (r_mcp.body_text or "").lower()
    root_body_low = (r_root.body_text or "").lower()
    root_final_low = (r_root.final_url or "").lower()
    root_title_low = (extract_html_title(r_root.body_text) if r_root.status == 200 else "").strip().lower()

    # Reject multi-tenant SSO portals (e.g., <customer>.okta.com / okta-emea.com)
    if (
        '"errorcode":"e0000022"' in mcp_body_low
        or '"errorcode": "e0000022"' in mcp_body_low
        or "/app/userhome" in root_final_low
        or root_title_low in ("sign in", "log in", "login")
    ):
        return False

    mcp_ct = (r_mcp.headers.get("content-type") or "").lower()
    root_ct = (r_root.headers.get("content-type") or "").lower()
    mcp_has_proto = bool(
        "text/event-stream" in mcp_ct
        or "mcp-session-id" in r_mcp.headers
        or any(
            tok in mcp_body_low
            for tok in ('"jsonrpc"', '"mcp"', "modelcontextprotocol", "mcp-session-id")
        )
    )

    # Reject HTML SPA catch-alls (e.g., <tenant>.grafana.net returning React HTML on /mcp)
    if ("text/html" in mcp_ct or "application/xhtml" in mcp_ct) and not mcp_has_proto:
        pass
    elif r_mcp.status in (200, 400):
        if mcp_has_proto:
            return True
    elif r_mcp.status in (401, 405, 406, 415):
        return True

    if (
        r_root.status in (401, 405, 406)
        and "text/html" not in root_ct
        and "application/xhtml" not in root_ct
        and '"errorcode":"e0000022"' not in root_body_low
    ):
        return True

    return False


def probe_vector2(
    client: PoliteHttpClient,
    target: BrandTarget,
    verified_domains: List[str],
    v1_data: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[Finding], List[str]]:
    """Run Vector 2 hardened external agentic perimeter audit.

    Returns (vector2_data, findings, newly_discovered_sibling_domains).
    """
    primary = registrable_domain(target.domain)
    aliases = target.normalized_aliases()
    newly_verified_siblings: Set[str] = set()

    # ------------------------------------------------------------------
    # 2A. Open DNS Standards: DNS-AID (_agent / _mcp) & DNSSEC
    # ------------------------------------------------------------------
    dns_aid = probe_dns_aid(client, primary)

    # ------------------------------------------------------------------
    # 2B. Multi-Provider CT Logs + Live TLS SAN Discovery
    # ------------------------------------------------------------------
    ct_result = query_ct_agent_subdomains(client, primary)
    discovered_hosts: Set[str] = {f"mcp.{primary}", f"agents.{primary}"}
    for h in ct_result.get("agent_subdomains") or []:
        discovered_hosts.add(h)

    # Also seed any official first-party remote hosts from V1 MCP Registry
    if v1_data:
        for entry in (v1_data.get("mcp_registry") or {}).get("entries") or []:
            if entry.get("classification") == "official_domain_anchored":
                for rem in entry.get("remotes") or []:
                    rh = url_host(str(rem.get("url") or ""))
                    if rh and host_matches_any(rh, verified_domains):
                        discovered_hosts.add(rh)

    # Also check sibling `mcp.<sibling>` if a verified sibling exists (e.g. mcp.notion.com)
    for sib in verified_domains:
        if sib != primary:
            discovered_hosts.add(f"mcp.{sib}")

    # Wildcard DNS check on primary domain
    wc_probe = doh_resolve(client, f"agent-perimeter-nx-9f8e7d.{primary}", ("A", "AAAA", "CNAME"), dnssec=False)
    wc_ips = set(
        wc_probe["records"].get("A", [])
        + wc_probe["records"].get("AAAA", [])
        + wc_probe["records"].get("CNAME", [])
    )
    has_wildcard = wc_probe["resolves"]

    # ------------------------------------------------------------------
    # 2C. Root Discovery Paths on Primary Apex
    # ------------------------------------------------------------------
    root_well_known: Dict[str, Any] = {}
    cross_domain_pointers: List[Dict[str, Any]] = []
    for path in WELL_KNOWN_PATHS:
        url = f"https://{primary}{path}"
        resp = client.get(url, timeout=6.0, max_bytes=131072, retries=0)
        ok, parsed, reason = _parse_json_discovery(resp)
        ep: Dict[str, Any] = {
            "url": url,
            "final_url": resp.final_url,
            "status": resp.status,
            "valid": ok,
            "reason": reason,
            "www_authenticate": resp.headers.get("www-authenticate"),
        }
        if ok and parsed:
            ep["keys"] = list(parsed.keys())[:25]
            ep["declared_endpoints"] = _extract_declared_endpoints(parsed)
            ep["authorization_servers"] = parsed.get("authorization_servers") or []
            ep["scopes_supported"] = parsed.get("scopes_supported") or []
            ep["raw_snippet"] = resp.body_text[:400]

            # Follow declared endpoints passively (add to host check list & detect cross-domain drift)
            for dep in ep["declared_endpoints"]:
                dh = url_host(dep)
                if not dh:
                    continue
                dreg = registrable_domain(dh)
                if dreg != primary:
                    is_sibling = dreg in verified_domains or any(a in dreg.split(".")[0] for a in aliases if len(a) >= 3)
                    if is_sibling:
                        newly_verified_siblings.add(dreg)
                        discovered_hosts.add(dh)
                    cross_domain_pointers.append(
                        {
                            "source_url": resp.final_url,
                            "target_url": dep,
                            "target_host": dh,
                            "target_domain": dreg,
                            "is_verified_sibling": is_sibling,
                        }
                    )
                else:
                    discovered_hosts.add(dh)
        root_well_known[path] = ep

    # Cap total subdomain candidates to keep Top-100 runtime crisp (prioritize mcp.*, agents.*, then CT hosts)
    def _host_sort_key(h: str) -> Tuple[int, str]:
        if h.startswith("mcp."):
            return (0, h)
        if h.startswith("agents."):
            return (1, h)
        return (2, h)

    ordered_hosts = sorted(discovered_hosts, key=_host_sort_key)[:8]

    # ------------------------------------------------------------------
    # 2D. Probe Live Agent Subdomains: DNS, TLS SAN, Passive HTTP & RFC 9728
    # ------------------------------------------------------------------
    subdomains: List[Dict[str, Any]] = []
    live_mcp_endpoints: List[Dict[str, Any]] = []
    rfc9728_records: List[Dict[str, Any]] = []
    broad_scope_hits: List[Dict[str, Any]] = []

    # Check if root itself published RFC 9728 metadata
    for rpath in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
        ep = root_well_known.get(rpath) or {}
        if ep.get("valid"):
            rec = {
                "host": primary,
                "url": ep["final_url"],
                "authorization_servers": ep.get("authorization_servers") or [],
                "scopes_supported": ep.get("scopes_supported") or [],
            }
            rfc9728_records.append(rec)

    for fqdn in ordered_hosts:
        dns_info = doh_resolve(client, fqdn, ("A", "AAAA", "CNAME"), dnssec=True)
        sub_ips = set(
            dns_info["records"].get("A", [])
            + dns_info["records"].get("AAAA", [])
            + dns_info["records"].get("CNAME", [])
        )
        is_wc = bool(has_wildcard and host_matches_any(fqdn, [primary]) and sub_ips and sub_ips == wc_ips)
        effectively_live = bool(dns_info["resolves"] and not is_wc)
        if not effectively_live:
            subdomains.append(
                {
                    "fqdn": fqdn,
                    "effectively_live": False,
                    "is_wildcard_match": is_wc,
                    "dnssec_ad": dns_info["dnssec_ad"],
                }
            )
            continue

        tls_info = inspect_tls_cert(fqdn, timeout=4.5)
        # Inspect TLS SANs for additional sibling/agent hostnames
        san_agent_hosts = [
            s.lstrip("*.")
            for s in (tls_info.get("sans") or [])
            if any(tok in s for tok in ("mcp.", "agents.", "-mcp.", "mcp-"))
        ]

        # Passive GET / and GET /mcp
        r_root = client.get(f"https://{fqdn}/", timeout=5.5, max_bytes=32768, retries=0)
        r_mcp = client.get(f"https://{fqdn}/mcp", timeout=5.5, max_bytes=16384, retries=0)

        # Check WWW-Authenticate resource_metadata header (RFC 9728 discovery via 401)
        www_auth_candidates = [
            r_root.headers.get("www-authenticate") or "",
            r_mcp.headers.get("www-authenticate") or "",
        ]
        header_metadata_url: Optional[str] = None
        for wa in www_auth_candidates:
            m = RESOURCE_METADATA_HEADER_RE.search(wa)
            if m:
                header_metadata_url = m.group(1)
                break

        # Probe RFC 9728 standard paths on this host (root + path-inserted /mcp)
        host_rfc9728: Optional[Dict[str, Any]] = None
        if header_metadata_url:
            host_rfc9728 = _fetch_rfc9728_from_url(client, header_metadata_url)

        if host_rfc9728 is None:
            for rpath in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
                r_wk = client.get(f"https://{fqdn}{rpath}", timeout=5.0, max_bytes=131072, retries=0)
                ok_wk, parsed_wk, _ = _parse_json_discovery(r_wk)
                if ok_wk and parsed_wk:
                    host_rfc9728 = {
                        "url": r_wk.final_url,
                        "resource": parsed_wk.get("resource"),
                        "authorization_servers": parsed_wk.get("authorization_servers") or [],
                        "scopes_supported": parsed_wk.get("scopes_supported") or [],
                        "bearer_methods_supported": parsed_wk.get("bearer_methods_supported") or [],
                    }
                    break

        # Also check /.well-known/mcp.json & agent-card.json on the live host
        host_cards: Dict[str, Any] = {}
        for cpath in ("/.well-known/mcp.json", "/.well-known/agent-card.json", "/.well-known/agent.json"):
            rc = client.get(f"https://{fqdn}{cpath}", timeout=4.5, max_bytes=65536, retries=0)
            ok_c, parsed_c, _ = _parse_json_discovery(rc)
            if ok_c and parsed_c:
                host_cards[cpath] = {
                    "url": rc.final_url,
                    "keys": list(parsed_c.keys())[:20],
                    "declared_endpoints": _extract_declared_endpoints(parsed_c),
                }

        # Determine if this live host is a confirmed active MCP/Agent endpoint (vs. generic redirect/404/SSO/SPA)
        has_mcp_protocol_signal = _has_confirmed_mcp_signal(
            fqdn=fqdn,
            r_root=r_root,
            r_mcp=r_mcp,
            host_rfc9728=host_rfc9728,
            host_cards=host_cards,
            header_metadata_url=header_metadata_url,
        )

        if host_rfc9728:
            rec = {"host": fqdn, **host_rfc9728}
            rfc9728_records.append(rec)
            # Check authorization_servers for cross-domain drift
            for auth_srv in host_rfc9728.get("authorization_servers") or []:
                ah = url_host(str(auth_srv))
                areg = registrable_domain(ah) if ah else ""
                if areg and areg != primary and areg not in verified_domains and areg not in newly_verified_siblings:
                    is_sib = any(a in areg.split(".")[0] for a in aliases if len(a) >= 3)
                    cross_domain_pointers.append(
                        {
                            "source_url": host_rfc9728["url"],
                            "target_url": str(auth_srv),
                            "target_host": ah,
                            "target_domain": areg,
                            "is_verified_sibling": is_sib,
                            "relation": "oauth_authorization_server",
                        }
                    )

        sub_entry: Dict[str, Any] = {
            "fqdn": fqdn,
            "effectively_live": True,
            "dnssec_ad": dns_info["dnssec_ad"],
            "tls": tls_info,
            "san_agent_hosts": san_agent_hosts[:15],
            "http_root": {
                "status": r_root.status,
                "final_url": r_root.final_url,
                "www_authenticate": r_root.headers.get("www-authenticate"),
                "title": extract_html_title(r_root.body_text) if r_root.status == 200 else None,
                "error": r_root.error,
            },
            "http_mcp": {
                "status": r_mcp.status,
                "final_url": r_mcp.final_url,
                "content_type": r_mcp.headers.get("content-type"),
                "www_authenticate": r_mcp.headers.get("www-authenticate"),
                "error": r_mcp.error,
            },
            "rfc9728": host_rfc9728,
            "header_resource_metadata": header_metadata_url,
            "discovery_cards": host_cards,
            "confirmed_mcp_endpoint": has_mcp_protocol_signal,
            "missing_rfc9728": bool(
                has_mcp_protocol_signal and fqdn.lower().startswith("mcp.") and host_rfc9728 is None
            ),
        }
        subdomains.append(sub_entry)
        if has_mcp_protocol_signal:
            live_mcp_endpoints.append(sub_entry)

    # Check OAuth scopes across all discovered RFC 9728 records (deduplicated by URL)
    seen_rfc_urls: Set[str] = set()
    for rec in rfc9728_records:
        u = rec.get("url") or ""
        if u in seen_rfc_urls:
            continue
        seen_rfc_urls.add(u)
        scopes = [str(s) for s in (rec.get("scopes_supported") or []) if s]
        if scopes:
            flagged_scopes, is_broad = _analyze_scopes(scopes)
            if is_broad:
                broad_scope_hits.append(
                    {
                        "host": rec.get("host"),
                        "url": u,
                        "total_scopes": len(scopes),
                        "flagged_scopes": flagged_scopes,
                        "all_scopes_sample": scopes[:25],
                    }
                )

    # ------------------------------------------------------------------
    # Generate Hardened V2 Findings (Zero Phase 0 FPs)
    # ------------------------------------------------------------------
    findings: List[Finding] = []
    missing_rfc9728_hosts = [e for e in live_mcp_endpoints if e.get("missing_rfc9728")]

    # Finding 2A: Missing RFC 9728 Metadata on Active MCP Endpoint
    if missing_rfc9728_hosts:
        defn = FINDING_DEFINITIONS["v2_missing_rfc9728_metadata"]
        evs = [
            Evidence(
                source="http_well_known",
                locator=f"https://{e['fqdn']}/.well-known/oauth-protected-resource",
                detail=(
                    f"Active endpoint `{e['fqdn']}` (GET / -> HTTP {e['http_root']['status']}, "
                    f"GET /mcp -> HTTP {e['http_mcp']['status']}) serves no RFC 9728 metadata "
                    f"at root, /mcp path-inserted, or WWW-Authenticate resource_metadata header."
                ),
                raw={
                    "fqdn": e["fqdn"],
                    "http_root_status": e["http_root"]["status"],
                    "http_mcp_status": e["http_mcp"]["status"],
                    "www_authenticate": e["http_mcp"].get("www_authenticate") or e["http_root"].get("www_authenticate"),
                },
            )
            for e in missing_rfc9728_hosts
        ]
        findings.append(
            Finding(
                rule_id="v2_missing_rfc9728_metadata",
                vector="V2",
                label=str(defn["label"]),
                severity="medium",
                title=(
                    f"{len(missing_rfc9728_hosts)} active MCP endpoint(s) lack RFC 9728 OAuth "
                    f"Protected Resource metadata"
                ),
                summary=(
                    f"Confirmed first-party MCP subdomain(s) ({', '.join(e['fqdn'] for e in missing_rfc9728_hosts)}) "
                    f"do not publish RFC 9728 metadata (/.well-known/oauth-protected-resource), forcing "
                    f"MCP clients to fall back to ad-hoc auth discovery or manual token configuration."
                ),
                owasp=owasp_list_for("v2_missing_rfc9728_metadata"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 2B: Broad OAuth Scope Declaration
    if broad_scope_hits:
        defn = FINDING_DEFINITIONS["v2_broad_oauth_scope_declaration"]
        evs = [
            Evidence(
                source="http_well_known",
                locator=h["url"],
                detail=(
                    f"{h['host']} advertises {h['total_scopes']} OAuth scope(s); broad/privileged "
                    f"scopes detected: {', '.join(h['flagged_scopes'][:8]) or 'high scope count'}"
                ),
                raw=h,
            )
            for h in broad_scope_hits
        ]
        findings.append(
            Finding(
                rule_id="v2_broad_oauth_scope_declaration",
                vector="V2",
                label=str(defn["label"]),
                severity="medium",
                title=(
                    f"Broad or high-privilege OAuth scopes declared on {len(broad_scope_hits)} "
                    f"RFC 9728 protected-resource endpoint(s)"
                ),
                summary=(
                    f"Public OAuth Protected Resource metadata for {target.domain} advertises broad, "
                    f"write/admin, or numerous scopes without least-privilege agent partitioning."
                ),
                owasp=owasp_list_for("v2_broad_oauth_scope_declaration"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 2C: Cross-Domain Perimeter Drift (Sibling Domain vs. Unverified 3P Delegation)
    sibling_drifts = [p for p in cross_domain_pointers if p.get("is_verified_sibling")]
    external_3p_drifts = [p for p in cross_domain_pointers if not p.get("is_verified_sibling")]

    if external_3p_drifts:
        defn = FINDING_DEFINITIONS["v2_cross_domain_3p_delegation"]
        evs = [
            Evidence(
                source="http_well_known",
                locator=p["source_url"],
                detail=f"{p['source_url']} delegates to external domain `{p['target_domain']}` ({p['target_url']})",
                raw=p,
            )
            for p in external_3p_drifts[:6]
        ]
        findings.append(
            Finding(
                rule_id="v2_cross_domain_3p_delegation",
                vector="V2",
                label=str(defn["label"]),
                severity="medium",
                title=(
                    f"External discovery metadata delegates across domain boundary to "
                    f"{len({p['target_domain'] for p in external_3p_drifts})} external domain(s)"
                ),
                summary=(
                    f"Public agent/OAuth discovery metadata on {target.domain} directs clients to "
                    f"non-apex domain(s) ({', '.join(sorted({p['target_domain'] for p in external_3p_drifts}))}) "
                    f"outside the primary domain boundary."
                ),
                owasp=owasp_list_for("v2_cross_domain_3p_delegation"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    if sibling_drifts:
        defn = FINDING_DEFINITIONS["v2_cross_domain_perimeter_drift"]
        evs = [
            Evidence(
                source="http_well_known",
                locator=p["source_url"],
                detail=(
                    f"Discovery document on `{primary}` points to sibling domain `{p['target_domain']}` "
                    f"({p['target_url']})"
                ),
                raw=p,
            )
            for p in sibling_drifts[:6]
        ]
        findings.append(
            Finding(
                rule_id="v2_cross_domain_perimeter_drift",
                vector="V2",
                label=str(defn["label"]),
                severity="low",
                title=(
                    f"Agentic discovery spans sibling domain(s): "
                    f"{', '.join(sorted({p['target_domain'] for p in sibling_drifts}))}"
                ),
                summary=(
                    f"External MCP/agent discovery on {primary} routes to sibling brand domain(s), "
                    f"which can complicate strict domain-pinned enterprise allowlists if undocumented."
                ),
                owasp=owasp_list_for("v2_cross_domain_perimeter_drift"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 2D: Informational DNS-AID / DNSSEC posture when live MCP perimeter exists
    if live_mcp_endpoints and not dns_aid["dns_aid_present"] and not dns_aid["apex_dnssec_ad"]:
        defn = FINDING_DEFINITIONS["v2_missing_dns_aid_dnssec"]
        findings.append(
            Finding(
                rule_id="v2_missing_dns_aid_dnssec",
                vector="V2",
                label=str(defn["label"]),
                severity="info",
                title=f"Active MCP perimeter on {primary} lacks DNSSEC and DNS-AID (_agent/_mcp) records",
                summary=(
                    f"{primary} operates {len(live_mcp_endpoints)} active MCP/agent endpoint(s) without "
                    f"DNSSEC validation (AD=false) or IETF DNS-AID SVCB/TXT discovery records."
                ),
                owasp=owasp_list_for("v2_missing_dns_aid_dnssec"),
                evidence=[
                    Evidence(
                        source="dns_doh",
                        locator=f"_agent.{primary} / _mcp.{primary}",
                        detail=(
                            f"apex_dnssec_ad={dns_aid['apex_dnssec_ad']}, "
                            f"dns_aid_records=0, live_mcp_endpoints={[e['fqdn'] for e in live_mcp_endpoints]}"
                        ),
                        raw=dns_aid,
                    )
                ],
                recommendation=str(defn["recommendation"]),
            )
        )

    v2_data: Dict[str, Any] = {
        "dns_aid": dns_aid,
        "ct_discovery": ct_result,
        "wildcard_dns_detected": has_wildcard,
        "root_well_known": {k: v for k, v in root_well_known.items() if v.get("valid") or v.get("status") == 401},
        "subdomains": subdomains,
        "rfc9728_endpoints": rfc9728_records,
        "broad_oauth_scopes": broad_scope_hits,
        "cross_domain_pointers": cross_domain_pointers,
        "flags": {
            "apex_dnssec_enabled": dns_aid["apex_dnssec_ad"],
            "dns_aid_present": dns_aid["dns_aid_present"],
            "ct_provider_used": ct_result.get("provider"),
            "ct_query_ok": bool(ct_result.get("ok")),
            "live_mcp_endpoint_count": len(live_mcp_endpoints),
            "live_mcp_endpoints": [e["fqdn"] for e in live_mcp_endpoints],
            "rfc9728_present_count": len(seen_rfc_urls),
            "missing_rfc9728_count": len(missing_rfc9728_hosts),
            "broad_oauth_scope_detected": len(broad_scope_hits) > 0,
            "cross_domain_drift_detected": len(cross_domain_pointers) > 0,
            "cross_domain_3p_delegation_detected": len(external_3p_drifts) > 0,
        },
    }
    return v2_data, findings, sorted(newly_verified_siblings)
