"""Vector 3 (Demoted Silent Sub-Check): High-Signal Active Lookalike Infrastructure.

Per Phase 0 Go/No-Go pivot:
  - Runs silently across high-signal agent domain permutations.
  - Suppresses ALL domain parking (GoDaddy /lander, 76.223.105.230, Sedo, Afternic, Dan,
    Hostinger, Bodis, ParkingCrew, Spaceship, Atom), Cloudflare HTTP 523 squatters,
    MarkMonitor/CSC defensive registrations, and unrelated generic businesses.
  - Emits findings ONLY when a non-brand lookalike domain actively serves:
      (1) /.well-known/mcp.json, /.well-known/agent.json, /.well-known/agent-card.json,
          /.well-known/oauth-protected-resource, or a live /mcp protocol endpoint; OR
      (2) an active phishing/deceptive warning interstitial (e.g., Cloudflare Suspected Phishing).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Set, Tuple

from .dns_ct import doh_resolve, host_matches_any, inspect_tls_cert, url_matches_any
from .http_client import PoliteHttpClient, extract_html_title
from .models import BrandTarget, Evidence, Finding
from .taxonomy import FINDING_DEFINITIONS, owasp_list_for

LOOKALIKE_TEMPLATES = (
    "mcp-{brand}.com",
    "{brand}-mcp.com",
    "agent-{brand}.com",
    "{brand}-agent.com",
    "ai-{brand}.com",
    "{brand}-ai.com",
)

# Known parking IPs and body/NS indicators (silently suppressed)
PARKED_IPS: Set[str] = {
    "76.223.105.230",  # GoDaddy / Afternic parking lander
    "13.248.169.48",   # GoDaddy / Afternic Global Accelerator
    "3.33.130.190",    # GoDaddy parking
    "15.197.148.33",   # GoDaddy parking
    "64.190.63.222",   # Sedo parking
    "208.91.197.27",   # Confluence Networks / catch-all parking
    "208.91.197.132",  # Confluence Networks / catch-all parking
}

PARKED_BODY_INDICATORS = (
    "domain is for sale",
    "buy this domain",
    "this domain is parked",
    "parking page",
    "window.location.href=\"/lander\"",
    "window.location.href='/lander'",
    "checkdomain parking",
    "appraise.net marketplace",
    "parked domain name on hostinger",
    "sds-spaceship",
    "sedoparking",
    "afternic",
    "dan.com",
    "hugedomains",
    "bodis.com",
    "parkingcrew",
    "godaddy.com/domainsearch",
    "domainmarket",
    "domains.atom.com",
    "inquire about this domain",
    "make an offer on this domain",
)

PARKED_NS_INDICATORS = (
    "spaceship.net",
    "atom.com",
    "sedoparking.com",
    "afternic.com",
    "dan.com",
    "bodis.com",
    "parkingcrew.net",
    "hugedomains.com",
    "above.com",
    "cashparking.com",
    "domaincontrol.com",
)

DEFENSIVE_REGISTRAR_INDICATORS = (
    "registered & protected by markmonitor",
    "markmonitor.com",
    "csc corporate domains",
    "cscglobal.com",
)

TITLE_PHISHING_INDICATORS = (
    "suspected phishing",
    "phishing site ahead",
    "deceptive site ahead",
    "phishing warning",
)

INTERSTITIAL_BODY_INDICATORS = (
    "cloudflare phishing warning",
    "this website has been reported for potential phishing",
    "phishing site ahead",
    "deceptive site ahead",
)


def _is_valid_json_obj(body: str) -> bool:
    s = body.lstrip()
    if not s.startswith("{"):
        return False
    try:
        return isinstance(json.loads(s), dict)
    except Exception:
        return False


def _looks_like_live_mcp_endpoint(
    status: int, content_type: str, www_auth: str, body: str, headers: Dict[str, str] | None = None
) -> bool:
    ct = (content_type or "").lower()
    wa = (www_auth or "").lower()
    hdrs = headers or {}
    # Reject HTML catch-all pages, login redirects, and parking landers
    if "text/html" in ct or "application/xhtml" in ct:
        return False
    if status in (200, 405, 406):
        if "text/event-stream" in ct or "mcp-session-id" in hdrs:
            return True
        if "application/json" in ct and _is_valid_json_obj(body):
            bl = body.lower()
            if '"jsonrpc"' in bl or '"mcp"' in bl or '"protocolversion"' in bl:
                return True
    if status == 401 and ("resource_metadata" in wa or "mcp" in wa):
        return True
    return False


def probe_vector3(
    client: PoliteHttpClient,
    target: BrandTarget,
    verified_domains: List[str],
) -> Tuple[Dict[str, Any], List[Finding]]:
    """Run demoted silent Vector 3 lookalike check; alert ONLY on active MCP/agent endpoints or phishing."""
    brand = target.brand.lower()
    # Skip very short/generic 2-char brands to avoid spurious lookalikes
    if len(brand) < 3:
        return {
            "skipped": True,
            "reason": "brand_token_too_short",
            "permutations_tested": 0,
            "active_agent_endpoints": [],
            "phishing_flagged": [],
            "suppressed_count": 0,
        }, []

    permutations = [tmpl.format(brand=brand) for tmpl in LOOKALIKE_TEMPLATES]
    active_agent_hits: List[Dict[str, Any]] = []
    phishing_hits: List[Dict[str, Any]] = []
    suppressed_summary: Dict[str, int] = {
        "nxdomain": 0,
        "defensive_brand_owned": 0,
        "parked_or_for_sale": 0,
        "http_523_or_unreachable": 0,
        "generic_non_agent_site": 0,
    }

    for perm in permutations:
        # Skip if permutation is already one of the brand's own verified domains
        if host_matches_any(perm, verified_domains):
            suppressed_summary["defensive_brand_owned"] += 1
            continue

        dns_info = doh_resolve(client, perm, ("A", "CNAME", "NS"), dnssec=False)
        if not dns_info["resolves"]:
            suppressed_summary["nxdomain"] += 1
            continue

        a_records = set(dns_info["records"].get("A", []))
        ns_joined = " ".join(dns_info["records"].get("NS", [])).lower()

        # Fast-suppress known parking IPs before HTTP
        if a_records and a_records.issubset(PARKED_IPS):
            suppressed_summary["parked_or_for_sale"] += 1
            continue

        # Passive GET root
        resp = client.get(f"https://{perm}/", timeout=4.5, max_bytes=32768, retries=0)
        if resp.status == 0:
            resp = client.get(f"http://{perm}/", timeout=4.0, max_bytes=32768, retries=0)

        # Suppress Cloudflare HTTP 523 / unreachable origins silently
        if resp.status in (0, 520, 521, 522, 523, 524, 525, 526):
            suppressed_summary["http_523_or_unreachable"] += 1
            continue

        title = extract_html_title(resp.body_text) if resp.body_text else ""
        body_low = (resp.body_text or "").lower()
        title_low = title.lower()

        # Check defensive ownership (redirect to verified domain or MarkMonitor/CSC)
        if (
            url_matches_any(resp.final_url, verified_domains)
            or any(ind in body_low or ind in title_low for ind in DEFENSIVE_REGISTRAR_INDICATORS)
            or "markmonitor" in ns_joined
            or "cscdns" in ns_joined
        ):
            suppressed_summary["defensive_brand_owned"] += 1
            continue

        # Check TLS SAN for defensive ownership
        tls_info = inspect_tls_cert(perm, timeout=3.5)
        if any(host_matches_any(s.lstrip("*."), verified_domains) for s in (tls_info.get("sans") or [])):
            suppressed_summary["defensive_brand_owned"] += 1
            continue

        # Check active phishing interstitial FIRST (match generic "suspected phishing" ONLY in <title>,
        # never inside HTTP 200 body prose like "Report suspected phishing to IT Security")
        matched_phish = [ind for ind in TITLE_PHISHING_INDICATORS if ind in title_low]
        for ind in INTERSTITIAL_BODY_INDICATORS:
            if ind in body_low and ind not in matched_phish:
                if "cloudflare" in ind and resp.status not in (403, 451):
                    continue
                matched_phish.append(ind)
        if matched_phish:
            phishing_hits.append(
                {
                    "domain": perm,
                    "url": resp.final_url,
                    "status": resp.status,
                    "title": title,
                    "matched_indicators": matched_phish,
                    "a_records": sorted(a_records),
                }
            )
            continue

        # Suppress domain parking / for-sale landers silently
        if (
            any(ind in body_low for ind in PARKED_BODY_INDICATORS)
            or any(ind in (resp.final_url or "").lower() for ind in PARKED_NS_INDICATORS)
            or ("domaincontrol.com" in ns_joined and ("/lander" in body_low or len(resp.body_text.strip()) < 2500))
        ):
            suppressed_summary["parked_or_for_sale"] += 1
            continue

        # Probe ONLY active agent/MCP endpoints on non-parked live lookalike
        active_signals: List[Dict[str, Any]] = []
        for wk_path in ("/.well-known/mcp.json", "/.well-known/agent.json", "/.well-known/oauth-protected-resource"):
            rwk = client.get(f"https://{perm}{wk_path}", timeout=3.5, max_bytes=32768, retries=0)
            if rwk.status == 200 and _is_valid_json_obj(rwk.body_text):
                active_signals.append(
                    {"path": wk_path, "url": rwk.final_url, "status": rwk.status, "snippet": rwk.body_text[:250]}
                )

        rmcp = client.get(f"https://{perm}/mcp", timeout=3.5, max_bytes=16384, retries=0)
        if _looks_like_live_mcp_endpoint(
            rmcp.status,
            rmcp.headers.get("content-type", ""),
            rmcp.headers.get("www-authenticate", ""),
            rmcp.body_text,
            headers=rmcp.headers,
        ):
            active_signals.append(
                {
                    "path": "/mcp",
                    "url": rmcp.final_url,
                    "status": rmcp.status,
                    "content_type": rmcp.headers.get("content-type"),
                    "www_authenticate": rmcp.headers.get("www-authenticate"),
                }
            )

        if active_signals:
            active_agent_hits.append(
                {
                    "domain": perm,
                    "root_status": resp.status,
                    "root_title": title,
                    "a_records": sorted(a_records),
                    "tls_issuer": tls_info.get("issuer_cn"),
                    "active_signals": active_signals,
                }
            )
        else:
            suppressed_summary["generic_non_agent_site"] += 1

    # Generate high-signal findings ONLY when active agent endpoints or phishing confirmed
    findings: List[Finding] = []
    if active_agent_hits:
        defn = FINDING_DEFINITIONS["v3_active_lookalike_agent_endpoint"]
        evs = [
            Evidence(
                source="http_lookalike",
                locator=h["active_signals"][0]["url"],
                detail=(
                    f"Third-party lookalike `{h['domain']}` serves active agent/MCP endpoint(s): "
                    f"{', '.join(s['path'] for s in h['active_signals'])}"
                ),
                raw=h,
            )
            for h in active_agent_hits
        ]
        findings.append(
            Finding(
                rule_id="v3_active_lookalike_agent_endpoint",
                vector="V3",
                label=str(defn["label"]),
                severity="critical",
                title=(
                    f"{len(active_agent_hits)} third-party lookalike domain(s) actively serving "
                    f"MCP or agent discovery endpoints"
                ),
                summary=(
                    f"Non-brand lookalike infrastructure ({', '.join(h['domain'] for h in active_agent_hits)}) "
                    f"actively responds on standard MCP/agent discovery paths outside {target.domain}."
                ),
                owasp=owasp_list_for("v3_active_lookalike_agent_endpoint"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    if phishing_hits:
        defn = FINDING_DEFINITIONS["v3_active_phishing_lookalike"]
        evs = [
            Evidence(
                source="http_lookalike",
                locator=h["url"],
                detail=(
                    f"Lookalike `{h['domain']}` (HTTP {h['status']}, title: `{h['title']}`) triggered "
                    f"active phishing warning indicator(s): {', '.join(h['matched_indicators'])}"
                ),
                raw=h,
            )
            for h in phishing_hits
        ]
        findings.append(
            Finding(
                rule_id="v3_active_phishing_lookalike",
                vector="V3",
                label=str(defn["label"]),
                severity="high",
                title=(
                    f"{len(phishing_hits)} agent-themed lookalike domain(s) returned phishing warning interstitials"
                ),
                summary=(
                    f"External lookalike domain(s) ({', '.join(h['domain'] for h in phishing_hits)}) "
                    f"returned third-party phishing or deceptive-site warning interstitials during passive HTTP "
                    f"inspection. Verify domain ownership and status before initiating abuse reporting."
                ),
                owasp=owasp_list_for("v3_active_phishing_lookalike"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    v3_data: Dict[str, Any] = {
        "skipped": False,
        "permutations_tested": len(permutations),
        "active_agent_endpoints": active_agent_hits,
        "phishing_flagged": phishing_hits,
        "suppressed_noise": suppressed_summary,
        "flags": {
            "has_active_lookalike_agent_endpoint": len(active_agent_hits) > 0,
            "has_active_phishing_lookalike": len(phishing_hits) > 0,
        },
    }
    return v3_data, findings
