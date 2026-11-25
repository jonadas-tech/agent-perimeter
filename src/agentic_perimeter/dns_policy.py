"""Open-standard Protective DNS Response Policy Zone (RPZ) and structured JSON
domain feed exporter for agentic-perimeter.

Generates vendor-neutral ISC BIND RPZ syntax (compatible with standard DNS
resolvers supporting RPZ) and a machine-readable JSON domain feed from a single
AuditReport or batch scan output:
  - Allowlist (`rpz-passthru.`): verified first-party MCP / Agent Door FQDNs
    and verified DNS-AID target hosts.
  - Block / Audit watchlist (`CNAME .` NXDOMAIN in `block` mode, `CNAME rpz-drop.`
    in `drop` mode, or `CNAME rpz-passthru.` with `; AUDIT` in `audit` mode):
    confirmed phishing-warning lookalikes, active lookalike agent endpoints,
    spoofed `_ans-badge` host-binding mismatch hosts, and dedicated unverified
    3P URL-path-token relay hosts.
  - Self-DoS protection: shared multi-tenant cloud/hosting/aggregator platforms
    (e.g., github.com, vercel.app, cloudflare.com, workers.dev, smithery.ai) are
    NEVER emitted as NXDOMAIN blocks and are downgraded to review-only `audit`.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import __version__
from .dns_ct import host_matches_any, registrable_domain, url_host
from .models import AuditReport

# Shared multi-tenant cloud, code hosting, edge compute, and MCP aggregator platforms.
# Never emit NXDOMAIN (CNAME .) for these domains to prevent enterprise self-DoS.
SHARED_MULTITENANT_PLATFORMS: Set[str] = {
    "github.com",
    "githubusercontent.com",
    "github.io",
    "gitlab.com",
    "vercel.app",
    "vercel.com",
    "netlify.app",
    "netlify.com",
    "cloudflare.com",
    "workers.dev",
    "pages.dev",
    "r2.dev",
    "trycloudflare.com",
    "amazonaws.com",
    "awsapprunner.com",
    "cloudfront.net",
    "azurewebsites.net",
    "azure.com",
    "googleapis.com",
    "run.app",
    "cloudfunctions.net",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "fly.dev",
    "render.com",
    "onrender.com",
    "railway.app",
    "herokuapp.com",
    "replit.app",
    "deno.dev",
    "supabase.co",
    "modal.run",
    "ngrok.io",
    "ngrok-free.app",
    "smithery.ai",
    "glama.ai",
    "composio.dev",
    "pipedream.net",
    "zapier.com",
    "make.com",
    "fastmcp.cloud",
    "apify.com",
    "npmjs.org",
    "pypi.org",
}

_VALID_FQDN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_VALID_POLICY_MODES = {"block", "audit", "drop"}


def _clean_fqdn(raw: Any) -> Optional[str]:
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip().lower().rstrip(".")
    if "://" in s:
        s = url_host(s)
    if s.startswith("*."):
        return None
    if not s or len(s) > 253 or not _VALID_FQDN_RE.match(s):
        return None
    # Reject IPv4 literals or all-numeric TLDs (RFC 1123/3696)
    if s.rsplit(".", 1)[-1].isdigit():
        return None
    return s


def _sanitize_comment(text: str) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(text or "")).strip()[:220]


def is_shared_multitenant_platform(fqdn: str) -> bool:
    """Return True if fqdn belongs to a shared multi-tenant cloud/hosting/aggregator platform."""
    clean = _clean_fqdn(fqdn)
    if not clean:
        return False
    reg = registrable_domain(clean)
    if reg in SHARED_MULTITENANT_PLATFORMS or clean in SHARED_MULTITENANT_PLATFORMS:
        return True
    return any(clean.endswith("." + p) for p in SHARED_MULTITENANT_PLATFORMS)


def _normalize_reports(report_or_batch: AuditReport | Dict[str, Any] | List[Any]) -> List[Dict[str, Any]]:
    if isinstance(report_or_batch, AuditReport):
        return [report_or_batch.to_dict()]
    if isinstance(report_or_batch, list):
        return [
            r.to_dict() if isinstance(r, AuditReport) else r
            for r in report_or_batch
            if isinstance(r, (AuditReport, dict))
        ]
    if isinstance(report_or_batch, dict):
        if isinstance(report_or_batch.get("reports"), list):
            return [
                r.to_dict() if isinstance(r, AuditReport) else r
                for r in report_or_batch["reports"]
                if isinstance(r, (AuditReport, dict))
            ]
        return [report_or_batch]
    return []


def _rdap_lookup_from_report(report: Dict[str, Any], fqdn: str) -> Dict[str, Any]:
    reg = registrable_domain(fqdn)
    rdap_tel = ((report.get("telemetry") or {}).get("rdap") or {}).get("domains") or {}
    if isinstance(rdap_tel, dict) and reg in rdap_tel and isinstance(rdap_tel[reg], dict):
        return rdap_tel[reg]
    return {}


def _extract_spoofed_ans_hosts(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract spoofed `_ans-badge` host-binding mismatch records from V2 and V3 linter output."""
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _collect(item: Dict[str, Any], source_vec: str, force_mismatch: bool = False) -> None:
        if not isinstance(item, dict):
            return
        mismatch = force_mismatch or bool(
            item.get("spoofed")
            or item.get("host_mismatch")
            or item.get("host_binding_mismatch")
            or item.get("host_binding_status") == "host_mismatch"
            or item.get("status") in ("mismatch", "spoofed", "host_mismatch")
            or item.get("host_binding_valid") is False
            or item.get("host_match") is False
        )
        if not mismatch:
            return
        host = _clean_fqdn(
            item.get("host")
            or item.get("dialed_host")
            or item.get("fqdn")
            or item.get("domain")
            or ""
        )
        if not host or host in seen:
            return
        seen.add(host)
        claimed = (
            item.get("receipt_host")
            or item.get("ans_name")
            or item.get("ansName")
            or item.get("ans_name_host")
            or "unknown"
        )
        out.append(
            {
                "fqdn": host,
                "source_vector": source_vec,
                "claimed_identity": str(claimed),
                "badge_url": item.get("receipt_url") or item.get("url") or "",
                "rdap": item.get("rdap") if isinstance(item.get("rdap"), dict) else None,
            }
        )

    v2 = report.get("vector2") or {}
    linter = v2.get("dns_aid_linter") or {}
    if isinstance(linter, dict):
        # Canonical v0.3.0 summary list from dns_aid_linter
        for item in linter.get("spoofed_ans_badge_hosts") or []:
            _collect(item, "V2", force_mismatch=True)
        # Per-agent ans_badge results from dns_aid_linter
        for rec in linter.get("agent_records") or []:
            if isinstance(rec, dict) and isinstance(rec.get("ans_badge"), dict):
                _collect(rec["ans_badge"], "V2")

    v3 = report.get("vector3") or {}
    for key in ("spoofed_ans_badge_hosts", "spoofed_ans_badges", "ans_badge_spoofing", "ans_badge_mismatches"):
        rows = v3.get(key)
        if isinstance(rows, list):
            for r in rows:
                _collect(r, "V3", force_mismatch=True)

    return out


def _extract_tampered_card_hosts(report: Dict[str, Any]) -> Set[str]:
    """Identify hosts whose DNS-AID `cap-sha256` card digest failed verification."""
    tampered: Set[str] = set()
    linter = (report.get("vector2") or {}).get("dns_aid_linter") or {}
    if not isinstance(linter, dict):
        return tampered
    for raw_h in linter.get("card_hash_mismatch_hosts") or []:
        h = _clean_fqdn(raw_h)
        if h:
            tampered.add(h)
    for rec in linter.get("agent_records") or []:
        if not isinstance(rec, dict):
            continue
        st = str((rec.get("card_verification") or {}).get("status") or "").lower()
        if st in ("mismatch", "tampered", "invalid"):
            h = _clean_fqdn(rec.get("target_host") or rec.get("qname"))
            if h:
                tampered.add(h)
    return tampered


def _extract_verified_dns_aid_hosts(
    report: Dict[str, Any],
    verified_domains: List[str],
    untrusted_hosts: Set[str],
) -> List[Dict[str, Any]]:
    """Extract verified first-party DNS-AID target and catalog hosts for the allowlist."""
    hosts: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    v2 = report.get("vector2") or {}
    linter = v2.get("dns_aid_linter") or {}
    v2_flags = v2.get("flags") or {}

    def _add_host(raw_h: Any, card_status: str, dnssec_ad: bool, qname: str) -> None:
        h = _clean_fqdn(raw_h)
        if not h or h in seen or h in untrusted_hosts:
            return
        if verified_domains and not host_matches_any(h, verified_domains):
            return
        seen.add(h)
        hosts.append(
            {
                "fqdn": h,
                "card_hash_status": card_status,
                "dnssec_ad": dnssec_ad,
                "qname": qname,
            }
        )

    if isinstance(linter, dict):
        for rec in linter.get("agent_records") or []:
            if not isinstance(rec, dict):
                continue
            cv = rec.get("card_verification") or {}
            st = str(cv.get("status") or "no_digest").lower()
            if st in ("mismatch", "tampered", "invalid"):
                continue
            badge = rec.get("ans_badge") or {}
            if isinstance(badge, dict) and (badge.get("spoofed") or badge.get("host_binding_status") == "host_mismatch"):
                continue
            _add_host(
                rec.get("target_host"),
                st,
                bool(rec.get("dnssec_ad")),
                str(rec.get("qname") or ""),
            )
        for raw_h in linter.get("verified_first_party_agent_fqdns") or []:
            _add_host(raw_h, "verified", bool(linter.get("index_dnssec_ad") or linter.get("apex_dnssec_ad")), "")

    for raw_h in v2_flags.get("verified_first_party_agent_fqdns") or []:
        _add_host(raw_h, "verified", bool(v2_flags.get("apex_dnssec_enabled")), "")

    return hosts


_CATEGORY_PRIORITY: Dict[str, int] = {
    "spoofed_ans_badge": 100,
    "phishing_lookalike": 95,
    "active_lookalike_agent_endpoint": 90,
    "url_path_token_relay": 80,
    "verified_first_party_mcp": 60,
    "verified_dns_aid_target": 55,
    "unverified_3p_hosted_proxy": 30,
}


def build_policy_entries(
    report_or_batch: AuditReport | Dict[str, Any] | List[Any],
    policy_mode: str = "block",
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Build normalized, deduplicated protective DNS policy entries from one or more AuditReports."""
    mode = (policy_mode or "block").strip().lower()
    if mode not in _VALID_POLICY_MODES:
        raise ValueError(f"Unsupported policy_mode {policy_mode!r}; expected one of {sorted(_VALID_POLICY_MODES)}")

    reports = _normalize_reports(report_or_batch)
    targets_included: List[str] = []
    entries_by_fqdn: Dict[str, Dict[str, Any]] = {}

    def _effective_risk_action(fqdn: str, desired_action: str) -> Tuple[str, Optional[str]]:
        if is_shared_multitenant_platform(fqdn):
            if desired_action == "block":
                return (
                    "audit",
                    "shared multi-tenant platform downgraded from block to audit to prevent self-DoS",
                )
            return ("audit", "shared multi-tenant platform (review-only audit)")
        if mode == "audit":
            return ("audit", None)
        return (desired_action, None)

    def _upsert(entry: Dict[str, Any]) -> None:
        fqdn = entry["fqdn"]
        existing = entries_by_fqdn.get(fqdn)
        if existing is None:
            entries_by_fqdn[fqdn] = entry
            return
        new_prio = _CATEGORY_PRIORITY.get(entry["category"], 0)
        old_prio = _CATEGORY_PRIORITY.get(existing["category"], 0)
        if new_prio > old_prio:
            merged_ev = list(entry.get("evidence") or []) + list(existing.get("evidence") or [])
            entry["evidence"] = merged_ev[:6]
            entries_by_fqdn[fqdn] = entry
        elif new_prio == old_prio:
            for ev in entry.get("evidence") or []:
                if ev not in existing["evidence"] and len(existing["evidence"]) < 6:
                    existing["evidence"].append(ev)

    for rep in reports:
        target = rep.get("target") or {}
        target_domain = str(target.get("domain") or "").strip().lower()
        if target_domain and target_domain not in targets_included:
            targets_included.append(target_domain)

        verified_domains: List[str] = [
            d.strip().lower()
            for d in (rep.get("verified_sibling_domains") or ([target_domain] if target_domain else []))
            if isinstance(d, str) and d.strip()
        ]
        v1 = rep.get("vector1") or {}
        v2 = rep.get("vector2") or {}
        v3 = rep.get("vector3") or {}

        spoofed_ans = _extract_spoofed_ans_hosts(rep)
        spoofed_hosts = {item["fqdn"] for item in spoofed_ans}
        tampered_hosts = _extract_tampered_card_hosts(rep)
        untrusted_hosts = spoofed_hosts | tampered_hosts

        # 1. Verified first-party MCP / Agent Door FQDNs -> allow (`rpz-passthru.`)
        for sub in v2.get("subdomains") or []:
            if not isinstance(sub, dict):
                continue
            if not (sub.get("effectively_live") and (sub.get("confirmed_mcp_endpoint") or sub.get("rfc9728"))):
                continue
            fqdn = _clean_fqdn(sub.get("fqdn"))
            if not fqdn or fqdn in untrusted_hosts:
                continue
            if verified_domains and not host_matches_any(fqdn, verified_domains):
                continue
            _upsert(
                {
                    "fqdn": fqdn,
                    "registrable_domain": registrable_domain(fqdn),
                    "action": "allow",
                    "category": "verified_first_party_mcp",
                    "confidence": "high",
                    "reason": f"Verified first-party active MCP/agent endpoint for {target_domain or fqdn}",
                    "owasp": ["ASI07", "MCP09:2025"],
                    "rdap_age_days": None,
                    "rdap_is_nod_30d": None,
                    "rdap_registrar": None,
                    "source_target": target_domain,
                    "evidence": [
                        {
                            "source": "v2_perimeter",
                            "fqdn": fqdn,
                            "confirmed_mcp_endpoint": bool(sub.get("confirmed_mcp_endpoint")),
                            "rfc9728_present": bool(sub.get("rfc9728")),
                            "dnssec_ad": bool(sub.get("dnssec_ad")),
                        }
                    ],
                }
            )

        # Also include any verified live_mcp_endpoints listed in v2 flags if not in subdomains list
        for raw_ep in (v2.get("flags") or {}).get("live_mcp_endpoints") or []:
            fqdn = _clean_fqdn(raw_ep)
            if not fqdn or fqdn in untrusted_hosts:
                continue
            if verified_domains and not host_matches_any(fqdn, verified_domains):
                continue
            if fqdn not in entries_by_fqdn:
                _upsert(
                    {
                        "fqdn": fqdn,
                        "registrable_domain": registrable_domain(fqdn),
                        "action": "allow",
                        "category": "verified_first_party_mcp",
                        "confidence": "high",
                        "reason": f"Verified first-party live MCP endpoint for {target_domain or fqdn}",
                        "owasp": ["ASI07", "MCP09:2025"],
                        "rdap_age_days": None,
                        "rdap_is_nod_30d": None,
                        "rdap_registrar": None,
                        "source_target": target_domain,
                        "evidence": [{"source": "v2_flags", "fqdn": fqdn}],
                    }
                )

        # 2. Verified DNS-AID target hosts -> allow (`rpz-passthru.`)
        for aid_host in _extract_verified_dns_aid_hosts(rep, verified_domains, untrusted_hosts):
            fqdn = aid_host["fqdn"]
            _upsert(
                {
                    "fqdn": fqdn,
                    "registrable_domain": registrable_domain(fqdn),
                    "action": "allow",
                    "category": "verified_dns_aid_target",
                    "confidence": "high",
                    "reason": (
                        f"Verified first-party DNS-AID target host for {target_domain or fqdn} "
                        f"(card_hash={aid_host['card_hash_status']}, dnssec_ad={aid_host['dnssec_ad']})"
                    ),
                    "owasp": ["ASI07", "MCP09:2025"],
                    "rdap_age_days": None,
                    "rdap_is_nod_30d": None,
                    "rdap_registrar": None,
                    "source_target": target_domain,
                    "evidence": [{"source": "dns_aid_linter", **aid_host}],
                }
            )

        # 3. Spoofed `_ans-badge` host-binding mismatch hosts (V2 & V3)
        for sp in spoofed_ans:
            fqdn = sp["fqdn"]
            action, platform_note = _effective_risk_action(fqdn, "block")
            rdap = sp.get("rdap") or _rdap_lookup_from_report(rep, fqdn)
            reason = (
                f"Passive _ans-badge host-binding mismatch: host {fqdn} publishes receipt "
                f"claiming identity {sp['claimed_identity']}"
            )
            if platform_note:
                reason = f"{reason} ({platform_note})"
            _upsert(
                {
                    "fqdn": fqdn,
                    "registrable_domain": registrable_domain(fqdn),
                    "action": action,
                    "category": "spoofed_ans_badge",
                    "confidence": "high",
                    "reason": reason,
                    "owasp": ["ASI04", "ASI07", "ASI09", "MCP04:2025", "MCP09:2025"],
                    "rdap_age_days": rdap.get("age_days"),
                    "rdap_is_nod_30d": rdap.get("is_nod_30d"),
                    "rdap_registrar": rdap.get("registrar"),
                    "source_target": target_domain,
                    "evidence": [
                        {
                            "source": f"{sp['source_vector'].lower()}_ans_badge",
                            "dialed_host": fqdn,
                            "claimed_identity": sp["claimed_identity"],
                            "badge_url": sp["badge_url"],
                        }
                    ],
                }
            )

        # 4. V3 Phishing-Warning Lookalike Domains
        for hit in v3.get("phishing_flagged") or []:
            if not isinstance(hit, dict):
                continue
            fqdn = _clean_fqdn(hit.get("domain"))
            if not fqdn:
                continue
            action, platform_note = _effective_risk_action(fqdn, "block")
            rdap = hit.get("rdap") if isinstance(hit.get("rdap"), dict) else _rdap_lookup_from_report(rep, fqdn)
            indicators = ", ".join(str(x) for x in (hit.get("matched_indicators") or [])[:3]) or "phishing interstitial"
            reason = f"Phishing-warning lookalike domain for {target_domain} (HTTP {hit.get('status')}, {indicators})"
            if platform_note:
                reason = f"{reason} ({platform_note})"
            _upsert(
                {
                    "fqdn": fqdn,
                    "registrable_domain": registrable_domain(fqdn),
                    "action": action,
                    "category": "phishing_lookalike",
                    "confidence": "high",
                    "reason": reason,
                    "owasp": ["ASI04", "ASI09", "MCP04:2025"],
                    "rdap_age_days": rdap.get("age_days"),
                    "rdap_is_nod_30d": rdap.get("is_nod_30d"),
                    "rdap_registrar": rdap.get("registrar"),
                    "source_target": target_domain,
                    "evidence": [
                        {
                            "source": "v3_phishing_lookalike",
                            "url": hit.get("url") or f"https://{fqdn}/",
                            "status": hit.get("status"),
                            "matched_indicators": hit.get("matched_indicators") or [],
                        }
                    ],
                }
            )

        # 5. V3 Active Lookalike Agent Endpoints
        for hit in v3.get("active_agent_endpoints") or []:
            if not isinstance(hit, dict):
                continue
            fqdn = _clean_fqdn(hit.get("domain"))
            if not fqdn:
                continue
            action, platform_note = _effective_risk_action(fqdn, "block")
            rdap = hit.get("rdap") if isinstance(hit.get("rdap"), dict) else _rdap_lookup_from_report(rep, fqdn)
            paths = ", ".join(
                str(s.get("path")) for s in (hit.get("active_signals") or []) if isinstance(s, dict) and s.get("path")
            ) or "/mcp"
            reason = f"Active lookalike agent/MCP endpoint for {target_domain} serving {paths}"
            if platform_note:
                reason = f"{reason} ({platform_note})"
            _upsert(
                {
                    "fqdn": fqdn,
                    "registrable_domain": registrable_domain(fqdn),
                    "action": action,
                    "category": "active_lookalike_agent_endpoint",
                    "confidence": "high",
                    "reason": reason,
                    "owasp": ["ASI04", "ASI07", "MCP09:2025"],
                    "rdap_age_days": rdap.get("age_days"),
                    "rdap_is_nod_30d": rdap.get("is_nod_30d"),
                    "rdap_registrar": rdap.get("registrar"),
                    "source_target": target_domain,
                    "evidence": [
                        {
                            "source": "v3_active_lookalike",
                            "domain": fqdn,
                            "active_paths": paths,
                        }
                    ],
                }
            )

        # 6. V1 Unverified 3P MCP URL-Path-Token Relay Hosts & Unverified 3P Proxies
        for entry in ((v1.get("mcp_registry") or {}).get("entries") or []):
            if not isinstance(entry, dict):
                continue
            is_tok = bool(entry.get("url_path_token_exposed"))
            is_3p = entry.get("classification") == "unverified_3p_hosted_proxy"
            if not (is_tok or is_3p):
                continue

            candidate_hosts: List[Tuple[str, str]] = []
            if is_tok:
                for u in entry.get("token_exposed_urls") or []:
                    h = _clean_fqdn(url_host(str(u)))
                    if h:
                        candidate_hosts.append((h, str(u)))
            for rem in entry.get("remotes") or []:
                if isinstance(rem, dict) and rem.get("url"):
                    h = _clean_fqdn(url_host(str(rem["url"])))
                    if h:
                        candidate_hosts.append((h, str(rem["url"])))
            if not candidate_hosts:
                for d in entry.get("remote_domains") or []:
                    h = _clean_fqdn(str(d))
                    if h:
                        candidate_hosts.append((h, f"https://{h}"))

            seen_entry_hosts: Set[str] = set()
            for fqdn, raw_url in candidate_hosts:
                if fqdn in seen_entry_hosts:
                    continue
                seen_entry_hosts.add(fqdn)
                if verified_domains and host_matches_any(fqdn, verified_domains):
                    continue

                reg = registrable_domain(fqdn)
                entry_rdap = (entry.get("remote_rdap") or {}).get(reg) if isinstance(entry.get("remote_rdap"), dict) else None
                rdap = entry_rdap if isinstance(entry_rdap, dict) else _rdap_lookup_from_report(rep, fqdn)

                if is_tok:
                    action, platform_note = _effective_risk_action(fqdn, "block")
                    reason = (
                        f"Unverified 3rd-party MCP registry entry ({entry.get('name')}) embeds "
                        f"credential/token template in remote URL on {fqdn}"
                    )
                    if platform_note:
                        reason = f"{reason} ({platform_note})"
                    _upsert(
                        {
                            "fqdn": fqdn,
                            "registrable_domain": reg,
                            "action": action,
                            "category": "url_path_token_relay",
                            "confidence": "high",
                            "reason": reason,
                            "owasp": ["ASI03", "ASI04", "MCP01:2025", "MCP04:2025"],
                            "rdap_age_days": rdap.get("age_days"),
                            "rdap_is_nod_30d": rdap.get("is_nod_30d"),
                            "rdap_registrar": rdap.get("registrar"),
                            "source_target": target_domain,
                            "evidence": [
                                {
                                    "source": "v1_mcp_registry",
                                    "server_name": entry.get("name"),
                                    "url": raw_url,
                                }
                            ],
                        }
                    )
                else:
                    # Standard unverified 3P hosted proxies are always review-only `audit`
                    # (never auto-NXDOMAIN to preserve neutrality and avoid breaking legitimate community tools)
                    _upsert(
                        {
                            "fqdn": fqdn,
                            "registrable_domain": reg,
                            "action": "audit",
                            "category": "unverified_3p_hosted_proxy",
                            "confidence": "medium",
                            "reason": (
                                f"Unverified 3rd-party hosted MCP proxy ({entry.get('name')}) referencing "
                                f"{target_domain or 'brand'} (review-only audit; not auto-blocked)"
                            ),
                            "owasp": ["ASI04", "ASI07", "MCP04:2025", "MCP09:2025"],
                            "rdap_age_days": rdap.get("age_days"),
                            "rdap_is_nod_30d": rdap.get("is_nod_30d"),
                            "rdap_registrar": rdap.get("registrar"),
                            "source_target": target_domain,
                            "evidence": [
                                {
                                    "source": "v1_mcp_registry",
                                    "server_name": entry.get("name"),
                                    "url": raw_url,
                                }
                            ],
                        }
                    )

    # Sort deterministically: allow -> block -> audit, then category priority desc, then fqdn asc
    action_rank = {"allow": 0, "block": 1, "audit": 2}
    ordered = sorted(
        entries_by_fqdn.values(),
        key=lambda e: (action_rank.get(e["action"], 9), -_CATEGORY_PRIORITY.get(e["category"], 0), e["fqdn"]),
    )
    return ordered, targets_included


def render_domain_feed(
    report_or_batch: AuditReport | Dict[str, Any] | List[Any],
    policy_mode: str = "block",
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Render a structured, vendor-neutral Protective DNS JSON domain feed."""
    entries, targets = build_policy_entries(report_or_batch, policy_mode=policy_mode)
    ts = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_action = Counter(e["action"] for e in entries)
    by_category = Counter(e["category"] for e in entries)

    return {
        "schema_version": "1.0",
        "feed_type": "agentic_perimeter_protective_dns_feed",
        "tool_version": __version__,
        "generated_at": ts,
        "policy_mode": (policy_mode or "block").strip().lower(),
        "targets_included": targets,
        "summary": {
            "total_entries": len(entries),
            "allow_count": by_action.get("allow", 0),
            "block_count": by_action.get("block", 0),
            "audit_count": by_action.get("audit", 0),
            "by_category": dict(sorted(by_category.items())),
        },
        "entries": entries,
    }


def render_rpz(
    report_or_batch: AuditReport | Dict[str, Any] | List[Any],
    zone_name: str = "rpz.agentic-perimeter.local",
    policy_mode: str = "block",
    generated_at: Optional[str] = None,
) -> str:
    """Render a standards-compliant, vendor-neutral ISC BIND Response Policy Zone (RPZ) file."""
    mode = (policy_mode or "block").strip().lower()
    if mode not in _VALID_POLICY_MODES:
        raise ValueError(f"Unsupported policy_mode {policy_mode!r}; expected one of {sorted(_VALID_POLICY_MODES)}")

    entries, targets = build_policy_entries(report_or_batch, policy_mode=mode)
    now_dt = datetime.now(timezone.utc)
    ts = generated_at or now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = now_dt.strftime("%Y%m%d01")

    clean_zone = _clean_fqdn(zone_name) or "rpz.agentic-perimeter.local"
    scope_desc = ", ".join(targets[:5]) + (f" (+{len(targets) - 5} more)" if len(targets) > 5 else "")
    scope_desc = _sanitize_comment(scope_desc or "unspecified")

    block_rdata = "rpz-drop." if mode == "drop" else "."
    block_label = "DROP" if mode == "drop" else "NXDOMAIN"

    lines: List[str] = [
        "; =============================================================================",
        "; agentic-perimeter Protective DNS Response Policy Zone (RPZ)",
        f"; Tool Version : {__version__}",
        f"; Zone Name    : {clean_zone}",
        f"; Generated    : {_sanitize_comment(ts)}",
        f"; Scope        : {scope_desc}",
        f"; Policy Mode  : {mode}",
        "; Format       : Open-standard DNS RPZ (RFC / ISC BIND syntax)",
        "; Notice       : Derived from 100% passive public observations. Classifications",
        ";                reflect factual technical signals; review prior to enforcement.",
        ";                Shared multi-tenant cloud platforms are audit-only (no NXDOMAIN).",
        "; =============================================================================",
        "$TTL 300",
        f"@   IN  SOA localhost. hostmaster.{clean_zone}. (",
        f"            {serial} ; serial",
        "            3600       ; refresh",
        "            900        ; retry",
        "            604800     ; expire",
        "            300 )      ; minimum TTL",
        "    IN  NS  localhost.",
        "",
    ]

    allow_entries = [e for e in entries if e["action"] == "allow"]
    block_entries = [e for e in entries if e["action"] == "block"]
    audit_entries = [e for e in entries if e["action"] == "audit"]

    lines.append(f"; --- Verified First-Party Allowlist ({len(allow_entries)}) ---")
    if not allow_entries:
        lines.append("; (none)")
    for e in allow_entries:
        note = _sanitize_comment(f"ALLOW [{e['category']}] {e['reason']}")
        lines.append(f"{e['fqdn']}  IN  CNAME  rpz-passthru. ; {note}")
    lines.append("")

    lines.append(f"; --- High-Confidence Risk Policy Triggers ({len(block_entries)}) ---")
    if not block_entries:
        lines.append("; (none)")
    for e in block_entries:
        age_tag = f" [rdap_age={e['rdap_age_days']}d]" if e.get("rdap_age_days") is not None else ""
        note = _sanitize_comment(f"BLOCK/{block_label} [{e['category']}]{age_tag} {e['reason']}")
        lines.append(f"{e['fqdn']}  IN  CNAME  {block_rdata} ; {note}")
    lines.append("")

    lines.append(f"; --- Audit / Review-Only Watchlist ({len(audit_entries)}) ---")
    if not audit_entries:
        lines.append("; (none)")
    for e in audit_entries:
        age_tag = f" [rdap_age={e['rdap_age_days']}d]" if e.get("rdap_age_days") is not None else ""
        note = _sanitize_comment(f"AUDIT [{e['category']}]{age_tag} {e['reason']}")
        lines.append(f"{e['fqdn']}  IN  CNAME  rpz-passthru. ; {note}")
    lines.append("")

    return "\n".join(lines)
