"""Deterministic 2-Axis External Agentic Exposure scoring and CISO-ready executive synthesis.

Scoring Model: `2-axis-v1`
  - Axis 1: First-Party Control Posture (0-100, higher = better, Grade A-F or N/A Baseline)
  - Axis 2: External Ecosystem Threat Pressure (0-100, higher = heavier pressure, Level None-Critical, NO letter grade)
  - 2D Executive Action Posture Matrix + Owner-Split Context-Aware Remediation Priorities
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import BrandTarget, Finding, ScoreSummary
from .taxonomy import ALL_FINDING_DEFINITIONS, FINDING_DEFINITIONS, axis_for

SCORING_MODEL = "2-axis-v1"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def _clean_points(val: float) -> int | float:
    return int(val) if float(val).is_integer() else round(float(val), 1)


def control_posture_grade_for(score: Optional[int]) -> Tuple[str, str]:
    if score is None:
        return "N/A", "Baseline (No Agentic Footprint)"
    if score >= 90:
        return "A", "Exemplary"
    if score >= 75:
        return "B", "Strong"
    if score >= 55:
        return "C", "Developing"
    if score >= 35:
        return "D", "Weak"
    return "F", "Critical Gap"


def threat_pressure_level_for(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    if score >= 1:
        return "Low"
    return "None"


def action_posture_for(grade: str, threat_level: str, domain: str) -> Tuple[str, str]:
    high_threat = threat_level in ("High", "Critical")
    mod_threat = threat_level == "Moderate"

    if grade == "N/A":
        if mod_threat or high_threat:
            return (
                "Brand Protection Alert",
                f"No active first-party agentic footprint detected for {domain}, but external lookalike or "
                f"ecosystem signals warrant Brand Protection review.",
            )
        return (
            "Baseline — Monitor",
            f"No external agentic footprint or third-party brand pressure detected for {domain}; "
            f"maintain passive registry monitoring and evaluate DNSSEC/DNS-AID ahead of adoption.",
        )

    if grade in ("A", "B"):
        if high_threat:
            return (
                "Active Defense",
                f"{domain} demonstrates strong first-party agentic controls while facing {threat_level.lower()} "
                f"external ecosystem threat pressure; focus on allowlist enforcement, developer advisories, and brand monitoring.",
            )
        if mod_threat:
            return (
                "Active Monitoring",
                f"{domain} maintains strong first-party controls with moderate third-party ecosystem activity; "
                f"monitor unverified proxies/packages and close remaining DNS trust gaps.",
            )
        return (
            "Well-Positioned",
            f"{domain} has strong first-party agentic controls and minimal external threat pressure; "
            f"sustain provenance hygiene and monitor for emerging namespace collisions.",
        )

    if grade == "C":
        if high_threat:
            return (
                "Priority Hardening",
                f"{domain} faces {threat_level.lower()} external threat pressure with developing first-party controls; "
                f"prioritize closing registry, package provenance, and RFC 9728 gaps.",
            )
        if mod_threat:
            return (
                "Hardening & Monitoring",
                f"{domain} has developing first-party controls amid moderate external activity; "
                f"complete official provenance controls and monitor unverified third-party packages.",
            )
        return (
            "Targeted Hardening",
            f"{domain} has an active agentic surface with low external pressure; close targeted "
            f"first-party OAuth, registry, or DNSSEC gaps proactively.",
        )

    # Weak: D or F
    if high_threat:
        return (
            "Urgent Remediation",
            f"{domain} faces {threat_level.lower()} external third-party pressure without sufficient first-party "
            f"agentic controls; immediately establish official registry/package provenance and harden MCP endpoints.",
        )
    if mod_threat:
        return (
            "Action Required",
            f"{domain} has material first-party control gaps alongside moderate external ecosystem pressure; "
            f"claim official provenance anchors and close active endpoint metadata gaps.",
        )
    return (
        "Proactive Hardening",
        f"{domain} operates an active external agentic surface with weak first-party controls; "
        f"remediate missing RFC 9728, registry, and DNSSEC gaps before external threat pressure intensifies.",
    )


def contextualize_recommendation(rule_id: str, v1_data: Dict[str, Any], default_rec: str) -> str:
    """Return a context-aware recommendation that never asks an org to claim assets it already owns."""
    v1_reg = v1_data.get("mcp_registry") or {}
    v1_npm = v1_data.get("npm") or {}
    v1_pypi = v1_data.get("pypi") or {}
    has_official_reg = (v1_reg.get("official_count") or 0) >= 1
    has_official_pkg = ((v1_npm.get("official_count") or 0) + (v1_pypi.get("official_count") or 0)) >= 1

    if rule_id == "v1_url_path_token_exposure":
        if has_official_reg:
            return (
                "Enforce internal MCP allowlists pinned to your verified first-party registry entry, "
                "publish a developer advisory rejecting remote MCP URLs that embed bearer tokens or "
                "API keys in URL paths, and review registry moderation options."
            )
        return (
            "Claim your official reverse-DNS namespace in registry.modelcontextprotocol.io (or publish "
            "an official policy statement), enforce internal MCP allowlists, and instruct developers/agents "
            "to reject remote MCP endpoints that pass bearer tokens or API keys in URL path templates."
        )

    if rule_id == "v1_unverified_3p_hosted_proxy":
        if has_official_reg:
            return (
                "Enforce internal MCP allowlists pinned to your verified first-party endpoint(s), "
                "prominently document your canonical reverse-DNS registry identifier, and monitor "
                "third-party proxies for unauthorized brand usage."
            )
        return (
            "Claim your official reverse-DNS namespace in registry.modelcontextprotocol.io (or publish "
            "an official policy statement) and enforce internal MCP allowlists pinned to verified first-party endpoints."
        )

    if rule_id == "v1_unscoped_free_email_collision":
        if has_official_pkg:
            return (
                "Verify npm/PyPI Trusted Publishers (OIDC provenance) on your existing official package(s), "
                "enforce allowlisted scopes in developer agent policies, and monitor public registries "
                "for unverified collisions."
            )
        return (
            "Publish official scoped MCP packages with verified domain provenance (npm/PyPI Trusted Publishers) "
            "and enforce allowlisted package scopes in developer agent policies."
        )

    if rule_id == "v1_unverified_package_collision":
        if has_official_pkg:
            return (
                "Prominently document canonical install commands (`npx` / `uvx`) pinned to your existing "
                "official package scope(s) and monitor public registries for unverified collisions."
            )
        return default_rec

    return default_rec


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.vector, f.rule_id),
    )


def score_audit(
    target: BrandTarget,
    findings: List[Finding],
    v1_data: Dict[str, Any],
    v2_data: Dict[str, Any],
    v3_data: Dict[str, Any],
) -> ScoreSummary:
    ordered = sort_findings(findings)

    # Ensure every finding has canonical axis and context-aware recommendation
    for f in ordered:
        if not f.axis:
            f.axis = axis_for(f.rule_id)
        f.recommendation = contextualize_recommendation(f.rule_id, v1_data, f.recommendation)

    counts_sev: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    counts_vec: Dict[str, int] = {"V1": 0, "V2": 0, "V3": 0}
    counts_axis: Dict[str, int] = {"first_party_control": 0, "external_threat": 0}

    for f in ordered:
        counts_sev[f.severity] = counts_sev.get(f.severity, 0) + 1
        counts_vec[f.vector] = counts_vec.get(f.vector, 0) + 1
        counts_axis[f.axis] = counts_axis.get(f.axis, 0) + 1

    v1_reg = v1_data.get("mcp_registry") or {}
    v1_npm = v1_data.get("npm") or {}
    v1_pypi = v1_data.get("pypi") or {}
    v1_flags = v1_data.get("flags") or {}
    v2_flags = v2_data.get("flags") or {}
    v3_flags = v3_data.get("flags") or {}

    official_reg_cnt = int(v1_reg.get("official_count") or 0)
    proxy_cnt = int(v1_reg.get("unverified_3p_hosted_proxy_count") or 0)
    token_cnt = int(v1_reg.get("url_path_token_exposed_count") or 0)
    unv_reg_pkg_cnt = int(v1_reg.get("unverified_3p_package_entry_count") or 0)

    npm_official = int(v1_npm.get("official_count") or 0)
    npm_unv = int(v1_npm.get("unverified_count") or 0)
    npm_free = int(v1_npm.get("free_email_unverified_count") or 0)
    npm_pkgs = v1_npm.get("packages") or []

    pypi_official = int(v1_pypi.get("official_count") or 0)
    pypi_unv = int(v1_pypi.get("unverified_count") or 0)
    pypi_free = int(v1_pypi.get("free_email_unverified_count") or 0)

    live_mcp = int(v2_flags.get("live_mcp_endpoint_count") or 0)
    rfc_present = int(v2_flags.get("rfc9728_present_count") or 0)
    missing_rfc = int(v2_flags.get("missing_rfc9728_count") or 0)
    broad_oauth = bool(v2_flags.get("broad_oauth_scope_detected"))
    cross_drift = bool(v2_flags.get("cross_domain_drift_detected"))
    cross_3p = bool(v2_flags.get("cross_domain_3p_delegation_detected"))
    dnssec_enabled = bool(v2_flags.get("apex_dnssec_enabled"))
    dns_aid_present = bool(v2_flags.get("dns_aid_present"))
    dns_aid_index_present = bool(v2_flags.get("dns_aid_index_present"))
    dns_aid_agent_count = int(v2_flags.get("dns_aid_agent_count") or 0)
    card_hash_verified = int(v2_flags.get("dns_aid_card_hash_verified_count") or 0)
    card_hash_mismatch = int(v2_flags.get("dns_aid_card_hash_mismatch_count") or 0)
    dane_tlsa_count = int(v2_flags.get("dane_tlsa_count") or 0)
    ans_badge_verified = int(v2_flags.get("ans_badge_verified_count") or 0)
    spoofed_ans_v2 = int(v2_flags.get("spoofed_ans_badge_count") or 0)

    # ------------------------------------------------------------------
    # Axis 1: First-Party Control Posture (0-100, higher = better; or N/A)
    # ------------------------------------------------------------------
    control_posture_applicable = bool(
        v1_flags.get("has_any_mcp_footprint")
        or live_mcp > 0
        or (npm_official + pypi_official) > 0
        or rfc_present > 0
        or cross_drift
        or cross_3p
        or dns_aid_index_present
        or dns_aid_agent_count > 0
        or spoofed_ans_v2 > 0
        or card_hash_mismatch > 0
    )

    control_breakdown: List[Dict[str, Any]] = []
    if not control_posture_applicable:
        control_posture_score: Optional[int] = None
        control_posture_grade, control_posture_label = control_posture_grade_for(None)
        dns_detail = (
            f"Apex DNSSEC: {'AD=true' if dnssec_enabled else 'AD=false'}; "
            f"IETF DNS-AID: {'present' if dns_aid_present else 'not detected'}"
        )
        control_breakdown = [
            {
                "id": "C1",
                "name": "Official MCP Registry Presence",
                "status": "na",
                "earned": None,
                "max_points": 35,
                "detail": "No external MCP ecosystem footprint detected",
            },
            {
                "id": "C2",
                "name": "Official Scoped / Anchored Packages",
                "status": "na",
                "earned": None,
                "max_points": 15,
                "detail": "No brand-named MCP npm or PyPI packages detected",
            },
            {
                "id": "C3",
                "name": "RFC 9728 OAuth Metadata Coverage",
                "status": "na",
                "earned": None,
                "max_points": 20,
                "detail": "No live first-party MCP endpoints detected",
            },
            {
                "id": "C4",
                "name": "Least-Privilege OAuth Scope Hygiene",
                "status": "na",
                "earned": None,
                "max_points": 10,
                "detail": "No live first-party MCP endpoints detected",
            },
            {
                "id": "C5",
                "name": "First-Party Domain Boundary Consistency",
                "status": "na",
                "earned": None,
                "max_points": 8,
                "detail": "No live first-party MCP endpoints or discovery drift detected",
            },
            {
                "id": "C6",
                "name": "Cryptographic DNS Trust (DNSSEC + DNS-AID)",
                "status": "baseline",
                "earned": None,
                "max_points": 12,
                "detail": f"Pre-adoption readiness baseline ({dns_detail})",
            },
        ]
    else:
        earned_sum = 0.0
        max_sum = 0.0

        # C1: Official MCP Registry Presence (35, applicable when an MCP registry, package, or live mcp.* footprint exists)
        has_mcp_c1_scope = bool(
            v1_flags.get("has_any_mcp_footprint") or live_mcp > 0 or (npm_official + pypi_official) > 0
        )
        if has_mcp_c1_scope:
            c1_earned = 35.0 if official_reg_cnt >= 1 else 0.0
            c1_status = "pass" if c1_earned == 35.0 else "gap"
            official_names = [
                e.get("name")
                for e in (v1_reg.get("entries") or [])
                if e.get("classification") == "official_domain_anchored" and e.get("name")
            ]
            c1_detail = (
                f"{_plural(official_reg_cnt, 'official domain-anchored entry', 'official domain-anchored entries')} "
                f"({', '.join(official_names[:2])})"
                if official_reg_cnt >= 1 and official_names
                else (
                    f"{_plural(official_reg_cnt, 'official domain-anchored entry', 'official domain-anchored entries')} verified"
                    if official_reg_cnt >= 1
                    else f"0 officially domain-anchored entries in Official MCP Registry for {target.domain}"
                )
            )
            control_breakdown.append(
                {
                    "id": "C1",
                    "name": "Official MCP Registry Presence",
                    "status": c1_status,
                    "earned": _clean_points(c1_earned),
                    "max_points": 35,
                    "detail": c1_detail,
                }
            )
            earned_sum += c1_earned
            max_sum += 35.0
        else:
            control_breakdown.append(
                {
                    "id": "C1",
                    "name": "Official MCP Registry Presence",
                    "status": "na",
                    "earned": None,
                    "max_points": 35,
                    "detail": "Not applicable (no MCP registry, package, or live mcp.* footprint detected)",
                }
            )

        # C2: Official Scoped / Anchored Packages (15, applicable if any npm/PyPI packages exist)
        total_pkgs = npm_official + pypi_official + npm_unv + pypi_unv
        if total_pkgs > 0:
            has_official_scoped_npm = any(
                p.get("official_anchored") and p.get("is_scoped") for p in npm_pkgs
            )
            has_official_pypi = pypi_official >= 1
            if has_official_scoped_npm or has_official_pypi:
                c2_earned = 15.0
                c2_status = "pass"
                parts = []
                if npm_official > 0:
                    parts.append(f"{npm_official} official npm")
                if pypi_official > 0:
                    parts.append(f"{pypi_official} official PyPI")
                c2_detail = f"Domain-anchored packages verified ({', '.join(parts)})"
            elif npm_official >= 1:
                c2_earned = 10.0
                c2_status = "partial"
                c2_detail = f"{npm_official} official unscoped npm package(s) verified (adopt @scope + Trusted Publishers)"
            else:
                c2_earned = 0.0
                c2_status = "gap"
                c2_detail = (
                    f"0 official npm/PyPI packages while {_plural(npm_unv + pypi_unv, 'unverified package')} claim '{target.brand}'"
                )
            control_breakdown.append(
                {
                    "id": "C2",
                    "name": "Official Scoped / Anchored Packages",
                    "status": c2_status,
                    "earned": _clean_points(c2_earned),
                    "max_points": 15,
                    "detail": c2_detail,
                }
            )
            earned_sum += c2_earned
            max_sum += 15.0
        else:
            control_breakdown.append(
                {
                    "id": "C2",
                    "name": "Official Scoped / Anchored Packages",
                    "status": "na",
                    "earned": None,
                    "max_points": 15,
                    "detail": "Not applicable (no brand-named npm or PyPI MCP packages detected)",
                }
            )

        # C3: RFC 9728 OAuth Metadata Coverage (20, applicable if live_mcp > 0)
        cov = 0.0
        if live_mcp > 0:
            covered = max(0, live_mcp - missing_rfc)
            cov = covered / live_mcp
            c3_earned = 20.0 * cov
            c3_status = "pass" if cov == 1.0 else ("partial" if cov > 0.0 else "gap")
            c3_detail = (
                f"{covered}/{live_mcp} live MCP {_plural(live_mcp, 'endpoint').split(' ', 1)[1]} "
                f"serve RFC 9728 OAuth Protected Resource metadata"
            )
            control_breakdown.append(
                {
                    "id": "C3",
                    "name": "RFC 9728 OAuth Metadata Coverage",
                    "status": c3_status,
                    "earned": _clean_points(c3_earned),
                    "max_points": 20,
                    "detail": c3_detail,
                }
            )
            earned_sum += c3_earned
            max_sum += 20.0
        else:
            control_breakdown.append(
                {
                    "id": "C3",
                    "name": "RFC 9728 OAuth Metadata Coverage",
                    "status": "na",
                    "earned": None,
                    "max_points": 20,
                    "detail": "Not applicable (no live first-party MCP endpoints detected)",
                }
            )

        # C4: Least-Privilege OAuth Scope Hygiene (10, applicable if live_mcp > 0)
        if live_mcp > 0:
            if rfc_present == 0:
                c4_earned = 0.0
                c4_status = "gap"
                c4_detail = "Unverifiable (0 live endpoints serve RFC 9728 OAuth metadata)"
            else:
                base_c4 = 3.0 if broad_oauth else 10.0
                c4_earned = base_c4 * cov
                c4_status = "pass" if c4_earned == 10.0 else ("partial" if c4_earned > 0.0 else "gap")
                if broad_oauth:
                    c4_detail = "Broad/administrative OAuth scope(s) declared in RFC 9728 metadata"
                elif cov < 1.0:
                    c4_detail = "No broad scopes on covered endpoints, but partial RFC 9728 coverage limits verification"
                else:
                    c4_detail = "No wildcard, admin, or overly broad OAuth scopes detected in RFC 9728 metadata"
            control_breakdown.append(
                {
                    "id": "C4",
                    "name": "Least-Privilege OAuth Scope Hygiene",
                    "status": c4_status,
                    "earned": _clean_points(c4_earned),
                    "max_points": 10,
                    "detail": c4_detail,
                }
            )
            earned_sum += c4_earned
            max_sum += 10.0
        else:
            control_breakdown.append(
                {
                    "id": "C4",
                    "name": "Least-Privilege OAuth Scope Hygiene",
                    "status": "na",
                    "earned": None,
                    "max_points": 10,
                    "detail": "Not applicable (no live first-party MCP endpoints detected)",
                }
            )

        # C5: First-Party Domain Boundary Consistency (8, applicable if live_mcp > 0 or drift/3p delegation)
        if live_mcp > 0 or cross_drift or cross_3p:
            has_verifiable_meta = (
                rfc_present > 0
                or bool(v2_data.get("root_well_known"))
                or any(bool(s.get("discovery_cards")) for s in (v2_data.get("subdomains") or []))
            )
            if cross_3p:
                c5_earned = 0.0
                c5_status = "gap"
                c5_detail = "Discovery metadata delegates to unverified third-party external domain(s)"
            elif cross_drift:
                c5_earned = 5.0
                c5_status = "partial"
                c5_detail = "Discovery metadata spans verified sibling brand domain(s) (document boundary explicitly)"
            elif has_verifiable_meta:
                c5_earned = 8.0
                c5_status = "pass"
                c5_detail = f"Discovery and OAuth metadata stay within {target.domain} first-party boundary"
            else:
                c5_earned = 0.0
                c5_status = "gap"
                c5_detail = "Live MCP endpoint(s) lack verifiable discovery/RFC 9728 metadata to confirm boundary"
            control_breakdown.append(
                {
                    "id": "C5",
                    "name": "First-Party Domain Boundary Consistency",
                    "status": c5_status,
                    "earned": _clean_points(c5_earned),
                    "max_points": 8,
                    "detail": c5_detail,
                }
            )
            earned_sum += c5_earned
            max_sum += 8.0
        else:
            control_breakdown.append(
                {
                    "id": "C5",
                    "name": "First-Party Domain Boundary Consistency",
                    "status": "na",
                    "earned": None,
                    "max_points": 8,
                    "detail": "Not applicable (no live first-party MCP endpoints or discovery drift detected)",
                }
            )

        # C6: Cryptographic DNS Trust (12 = 8 DNSSEC + 4 DNS-AID, always applicable)
        dns_aid_integrity_ok = card_hash_mismatch == 0 and spoofed_ans_v2 == 0
        c6_dns_aid_pts = 4.0 if (dns_aid_present and dns_aid_integrity_ok) else 0.0
        c6_earned = (8.0 if dnssec_enabled else 0.0) + c6_dns_aid_pts
        c6_status = "pass" if c6_earned == 12.0 else ("partial" if c6_earned > 0.0 else "gap")
        c6_extras: List[str] = []
        if card_hash_mismatch > 0:
            c6_extras.append(f"{card_hash_mismatch} card-digest mismatch")
        elif card_hash_verified > 0:
            c6_extras.append(f"{card_hash_verified} card digest verified")
        if dane_tlsa_count > 0:
            c6_extras.append(f"DANE TLSA on {dane_tlsa_count} host(s)")
        if spoofed_ans_v2 > 0:
            c6_extras.append(f"{spoofed_ans_v2} ANS badge host mismatch")
        elif ans_badge_verified > 0:
            c6_extras.append(f"{ans_badge_verified} ANS badge verified")
        extra_clause = f" ({'; '.join(c6_extras)})" if c6_extras else ""
        dns_aid_c6_str = (
            "present (+4)"
            if (dns_aid_present and dns_aid_integrity_ok)
            else ("present with integrity/binding failure (0/4)" if dns_aid_present else "not detected (0/4)")
        )
        c6_detail = (
            f"Apex DNSSEC: {'AD=true (+8)' if dnssec_enabled else 'AD=false (0/8)'}; "
            f"IETF DNS-AID: {dns_aid_c6_str}{extra_clause}"
        )
        control_breakdown.append(
            {
                "id": "C6",
                "name": "Cryptographic DNS Trust (DNSSEC + DNS-AID)",
                "status": c6_status,
                "earned": _clean_points(c6_earned),
                "max_points": 12,
                "detail": c6_detail,
            }
        )
        earned_sum += c6_earned
        max_sum += 12.0

        control_posture_score = int(round(100.0 * earned_sum / max_sum)) if max_sum > 0 else 0
        control_posture_grade, control_posture_label = control_posture_grade_for(control_posture_score)

    # ------------------------------------------------------------------
    # Axis 2: External Ecosystem Threat Pressure (0-100, NO A-F grade)
    # ------------------------------------------------------------------
    t1_pts = 35 if token_cnt >= 1 else 0
    if proxy_cnt >= 10:
        t2_pts = 32
    elif proxy_cnt >= 3:
        t2_pts = 26
    elif proxy_cnt >= 1:
        t2_pts = 20
    elif unv_reg_pkg_cnt >= 1:
        t2_pts = 6
    else:
        t2_pts = 0

    free_total = npm_free + pypi_free
    if free_total >= 10:
        t3_pts = 22
    elif free_total >= 3:
        t3_pts = 18
    elif free_total >= 1:
        t3_pts = 14
    else:
        t3_pts = 0

    unv_pkg_total = npm_unv + pypi_unv
    if unv_pkg_total >= 15:
        t4_pts = 12
    elif unv_pkg_total >= 5:
        t4_pts = 9
    elif unv_pkg_total >= 1:
        t4_pts = 6
    else:
        t4_pts = 0

    has_v3_agent = bool(v3_flags.get("has_active_lookalike_agent_endpoint"))
    has_v3_phish = bool(v3_flags.get("has_active_phishing_lookalike"))
    has_v3_spoofed_ans = bool(v3_flags.get("has_spoofed_ans_badge_lookalike"))
    v3_agent_cnt = len(v3_data.get("active_agent_endpoints") or []) if has_v3_agent else 0
    v3_phish_cnt = len(v3_data.get("phishing_flagged") or []) if has_v3_phish else 0
    v3_spoofed_ans_cnt = len(v3_data.get("spoofed_ans_badge_hosts") or []) if has_v3_spoofed_ans else 0
    t5_pts = 50 if has_v3_agent else 0
    t6_pts = 25 if has_v3_phish else 0
    t7_pts = 50 if has_v3_spoofed_ans else 0

    threat_breakdown: List[Dict[str, Any]] = [
        {
            "id": "T1",
            "name": "URL-Path Token Exposure (3P Proxy)",
            "points": t1_pts,
            "count": token_cnt,
            "detail": (
                f"{_plural(token_cnt, 'unverified 3P proxy', 'unverified 3P proxies')} expose token/key templates in remote URLs"
                if token_cnt > 0
                else "None detected"
            ),
        },
        {
            "id": "T2",
            "name": "Unverified 3P Hosted MCP Proxies",
            "points": t2_pts,
            "count": proxy_cnt if proxy_cnt > 0 else unv_reg_pkg_cnt,
            "detail": (
                f"{_plural(proxy_cnt, 'unverified 3P hosted proxy', 'unverified 3P hosted proxies')} in Official MCP Registry"
                if proxy_cnt > 0
                else (
                    f"{_plural(unv_reg_pkg_cnt, 'unverified 3P package-only registry entry', 'unverified 3P package-only registry entries')}"
                    if unv_reg_pkg_cnt > 0
                    else "None detected"
                )
            ),
        },
        {
            "id": "T3",
            "name": "Free-Email Maintainer Collisions",
            "points": t3_pts,
            "count": free_total,
            "detail": (
                f"{_plural(free_total, 'unverified package')} maintained via consumer free-email accounts (npm + PyPI)"
                if free_total > 0
                else "None detected"
            ),
        },
        {
            "id": "T4",
            "name": "Unverified Brand-Named Packages",
            "points": t4_pts,
            "count": unv_pkg_total,
            "detail": (
                f"{_plural(unv_pkg_total, 'unverified brand-named MCP package')} across npm ({npm_unv}) and PyPI ({pypi_unv})"
                if unv_pkg_total > 0
                else "None detected"
            ),
        },
        {
            "id": "T5",
            "name": "Active Lookalike Agent / MCP Endpoint",
            "points": t5_pts,
            "count": v3_agent_cnt,
            "detail": (
                f"{_plural(v3_agent_cnt, 'third-party lookalike domain')} actively serving MCP/agent endpoints"
                if has_v3_agent
                else "None detected"
            ),
        },
        {
            "id": "T6",
            "name": "Phishing-Warning Lookalike Domain",
            "points": t6_pts,
            "count": v3_phish_cnt,
            "detail": (
                f"{_plural(v3_phish_cnt, 'agent-themed lookalike domain')} returned phishing warning interstitials"
                if has_v3_phish
                else "None detected"
            ),
        },
        {
            "id": "T7",
            "name": "Spoofed ANS Badge Lookalike",
            "points": t7_pts,
            "count": v3_spoofed_ans_cnt,
            "detail": (
                f"{_plural(v3_spoofed_ans_cnt, 'lookalike host')} publish a copied `_ans-badge` bound to another FQDN"
                if has_v3_spoofed_ans
                else "None detected"
            ),
        },
    ]

    threat_pressure_score = min(100, t1_pts + t2_pts + t3_pts + t4_pts + t5_pts + t6_pts + t7_pts)
    threat_pressure_level = threat_pressure_level_for(threat_pressure_score)

    # ------------------------------------------------------------------
    # 2D Action Posture Synthesis
    # ------------------------------------------------------------------
    action_posture, action_posture_summary = action_posture_for(
        control_posture_grade, threat_pressure_level, target.domain
    )

    # ------------------------------------------------------------------
    # 30-Second CISO Executive Brief (3 tight, factual bullets)
    # ------------------------------------------------------------------
    takeaways: List[str] = []

    # Bullet 1: First-Party Control Posture
    if not control_posture_applicable:
        takeaways.append(
            f"First-party posture is Baseline (N/A): no external MCP registry footprint, brand-named packages, "
            f"or live first-party `mcp.{target.domain}` endpoints were detected."
        )
    else:
        passing = [c["id"] for c in control_breakdown if c["status"] == "pass"]
        gaps = [c["name"] for c in control_breakdown if c["status"] in ("gap", "partial")]
        gap_clause = f"Remaining gaps: {', '.join(gaps[:3])}." if gaps else "All applicable controls passed."
        takeaways.append(
            f"First-Party Control Posture is Grade {control_posture_grade} ({control_posture_score}/100, "
            f"{control_posture_label}) across {len([c for c in control_breakdown if c['status'] != 'na'])} "
            f"applicable controls ({len(passing)} passing). {gap_clause}"
        )

    # Bullet 2: External Ecosystem Threat Pressure
    if threat_pressure_score == 0:
        takeaways.append(
            f"External Threat Pressure is None (0/100): no unverified third-party MCP proxies, brand-named "
            f"package collisions, or active lookalike alerts were observed for '{target.brand}'."
        )
    else:
        drivers: List[str] = []
        if token_cnt > 0:
            drivers.append(f"{_plural(token_cnt, 'URL-path token exposed 3P proxy', 'URL-path token exposed 3P proxies')}")
        if proxy_cnt > 0:
            drivers.append(f"{_plural(proxy_cnt, 'unverified 3P hosted proxy', 'unverified 3P hosted proxies')}")
        elif unv_reg_pkg_cnt > 0:
            drivers.append(f"{_plural(unv_reg_pkg_cnt, 'unverified 3P registry entry', 'unverified 3P registry entries')}")
        if unv_pkg_total > 0:
            drivers.append(f"{_plural(unv_pkg_total, 'unverified npm/PyPI package')} ({free_total} free-email)")
        if has_v3_agent:
            drivers.append(f"{_plural(v3_agent_cnt, 'active lookalike MCP endpoint')}")
        if has_v3_phish:
            drivers.append(f"{_plural(v3_phish_cnt, 'phishing-warning lookalike domain')}")
        if has_v3_spoofed_ans:
            drivers.append(f"{_plural(v3_spoofed_ans_cnt, 'spoofed ANS badge lookalike host')}")
        takeaways.append(
            f"External Threat Pressure is {threat_pressure_level} ({threat_pressure_score}/100), driven by "
            f"{'; '.join(drivers)} — compared to {_plural(official_reg_cnt, 'official domain-anchored registry entry', 'official domain-anchored registry entries')}."
        )

    # Bullet 3: Perimeter & Cryptographic DNS Trust
    dns_aid_str = "present" if dns_aid_present else "not detected"
    dnssec_str = "validated (AD=true)" if dnssec_enabled else "not validated (AD=false)"
    if live_mcp > 0:
        takeaways.append(
            f"External perimeter: {_plural(live_mcp, 'live first-party MCP endpoint')} discovered "
            f"({live_mcp - missing_rfc}/{live_mcp} with RFC 9728 metadata); apex DNSSEC is {dnssec_str} and IETF DNS-AID is {dns_aid_str}."
        )
    else:
        takeaways.append(
            f"External perimeter: no active first-party `mcp.{target.domain}` endpoint discovered; "
            f"apex DNSSEC is {dnssec_str} and IETF DNS-AID is {dns_aid_str}."
        )

    # ------------------------------------------------------------------
    # Owner-Split Prioritized Action Plan (Context-Aware)
    # ------------------------------------------------------------------
    first_party_priorities: List[str] = []
    if control_posture_applicable:
        c_by_id = {c["id"]: c for c in control_breakdown}
        if c_by_id["C1"]["status"] == "gap":
            first_party_priorities.append(
                f"[Official MCP Registry] Claim the reverse-DNS namespace for {target.domain} in "
                f"registry.modelcontextprotocol.io (or publish an official MCP policy statement) to close the Registry Vacuum."
            )
        if c_by_id["C3"]["status"] in ("gap", "partial"):
            first_party_priorities.append(
                "[RFC 9728 OAuth Metadata] Serve /.well-known/oauth-protected-resource (and emit WWW-Authenticate "
                "resource_metadata headers on HTTP 401) across all active MCP endpoints."
            )
        if c_by_id["C2"]["status"] in ("gap", "partial"):
            if c_by_id["C2"]["status"] == "gap":
                first_party_priorities.append(
                    "[Official Packages] Publish official scoped npm/PyPI MCP packages using Trusted Publishers (OIDC provenance)."
                )
            else:
                first_party_priorities.append(
                    "[Official Packages] Migrate official unscoped npm MCP packages to a verified corporate @scope with Trusted Publishers."
                )
        if c_by_id["C4"]["status"] in ("gap", "partial") and rfc_present > 0:
            first_party_priorities.append(
                "[OAuth Scope Hygiene] Partition OAuth Protected Resource scopes into least-privilege read-only vs. admin/write scopes."
            )
        if c_by_id["C5"]["status"] in ("gap", "partial"):
            if cross_3p:
                first_party_priorities.append(
                    "[Domain Boundary] Audit and restrict unverified third-party external delegation in agent discovery documents."
                )
            elif cross_drift:
                first_party_priorities.append(
                    "[Domain Boundary] Explicitly document verified sibling domains referenced by agent discovery metadata."
                )
        if c_by_id["C6"]["status"] in ("gap", "partial"):
            if card_hash_mismatch > 0:
                first_party_priorities.append(
                    "[DNS-AID Integrity] Re-verify the live agent card at `key65400` (`cap`) against "
                    "`key65401` (`cap-sha256`) and publish matching SHA-256 digests atomically."
                )
            if spoofed_ans_v2 > 0:
                first_party_priorities.append(
                    "[ANS Badge Binding] Remediate `_ans-badge` host-binding mismatch(es) so transparency "
                    "log receipts strictly match the serving FQDN."
                )
            if not dnssec_enabled:
                next_grade_hint = (
                    f" to advance Control Posture from {control_posture_grade} ({control_posture_score}/100) to A"
                    if control_posture_grade == "B" and (control_posture_score or 0) >= 82
                    else ""
                )
                first_party_priorities.append(
                    f"[Cryptographic DNS] Enable apex DNSSEC (AD=true) and evaluate IETF DNS-AID "
                    f"(`_agent` / `_mcp` SVCB){next_grade_hint}."
                )
            elif not dns_aid_present:
                first_party_priorities.append(
                    "[Cryptographic DNS] Evaluate IETF DNS-AID (`_agent` / `_mcp` SVCB records) to complement apex DNSSEC."
                )
    else:
        if not dnssec_enabled:
            first_party_priorities.append(
                f"[Proactive Baseline] Enable apex DNSSEC (AD=true) on {target.domain} and monitor Official MCP Registry "
                f"and npm/PyPI ahead of future agentic adoption."
            )

    external_defense_priorities: List[str] = []
    seen_ext_recs = set()
    for f in ordered:
        if f.axis == "external_threat" and f.severity in ("critical", "high", "medium"):
            if f.recommendation not in seen_ext_recs:
                seen_ext_recs.add(f.recommendation)
                external_defense_priorities.append(f"[{f.label}] {f.recommendation}")
        if len(external_defense_priorities) >= 3:
            break

    # Merged top 3 for concise CLI/backward readability
    merged: List[str] = []
    for item in [*first_party_priorities[:2], *external_defense_priorities[:2], *first_party_priorities[2:], *external_defense_priorities[2:]]:
        if item not in merged:
            merged.append(item)
        if len(merged) >= 3:
            break
    if not merged:
        merged.append(
            "Maintain proactive monitoring of Official MCP Registry, npm/PyPI namespaces, and evaluate "
            "IETF DNS-AID (`_agent` / `_mcp` SVCB) + DNSSEC for verifiable external agent discovery."
        )

    return ScoreSummary(
        scoring_model=SCORING_MODEL,
        control_posture_score=control_posture_score,
        control_posture_grade=control_posture_grade,
        control_posture_label=control_posture_label,
        control_posture_applicable=control_posture_applicable,
        control_breakdown=control_breakdown,
        threat_pressure_score=threat_pressure_score,
        threat_pressure_level=threat_pressure_level,
        threat_breakdown=threat_breakdown,
        action_posture=action_posture,
        action_posture_summary=action_posture_summary,
        counts_by_severity=counts_sev,
        counts_by_vector=counts_vec,
        counts_by_axis=counts_axis,
        ciso_takeaways=takeaways,
        first_party_priorities=first_party_priorities[:4],
        external_defense_priorities=external_defense_priorities[:3],
        top_priorities=merged,
    )


def rescore_report_dict(report_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Re-score an existing serialized AuditReport dict with the canonical 2-axis model,
    refreshing finding axes, factual labels, and context-aware recommendations.
    """
    from .models import Evidence
    from .taxonomy import OwaspRef

    tgt_raw = report_dict.get("target") or {}
    target = BrandTarget(
        domain=str(tgt_raw.get("domain") or ""),
        brand=str(tgt_raw.get("brand") or ""),
        aliases=list(tgt_raw.get("aliases") or []),
        sector=str(tgt_raw.get("sector") or "Unknown"),
        cohort=str(tgt_raw.get("cohort") or "custom"),
        exclude_terms=list(tgt_raw.get("exclude_terms") or []),
        known_sibling_domains=list(tgt_raw.get("known_sibling_domains") or []),
    )
    v1_data = report_dict.get("vector1") or {}
    v2_data = report_dict.get("vector2") or {}
    v3_data = report_dict.get("vector3") or {}

    findings_objs: List[Finding] = []
    for fdict in report_dict.get("findings") or []:
        rid = str(fdict.get("rule_id") or "")
        defn = ALL_FINDING_DEFINITIONS.get(rid) or {}
        owasp_refs = [
            OwaspRef(
                framework=str(o.get("framework") or ""),
                code=str(o.get("code") or ""),
                title=str(o.get("title") or ""),
            )
            for o in (fdict.get("owasp") or [])
        ]
        ev_objs = [
            Evidence(
                source=str(e.get("source") or ""),
                locator=str(e.get("locator") or ""),
                detail=str(e.get("detail") or ""),
                raw=dict(e.get("raw") or {}),
            )
            for e in (fdict.get("evidence") or [])
        ]
        # Refresh canonical factual neutral labels & V3 phishing neutral copy if re-scoring older JSON
        label = str(defn.get("label") or fdict.get("label") or "")
        title = str(fdict.get("title") or "")
        summary = str(fdict.get("summary") or "")
        default_rec = str(defn.get("recommendation") or fdict.get("recommendation") or "")

        if rid == "v3_active_phishing_lookalike":
            phish_hits = v3_data.get("phishing_flagged") or []
            domains_str = ", ".join(h.get("domain", "") for h in phish_hits if h.get("domain"))
            n_hits = len(phish_hits) or 1
            title = f"{_plural(n_hits, 'agent-themed lookalike domain')} returned phishing warning interstitials"
            summary = (
                f"External lookalike domain(s) ({domains_str}) returned third-party phishing or deceptive-site "
                f"warning interstitials during passive HTTP inspection. Verify domain ownership and status before "
                f"initiating abuse reporting."
            )
        elif rid == "v1_unverified_3p_hosted_proxy" and "route agent requests/OAuth sessions" in summary:
            v1_reg = v1_data.get("mcp_registry") or {}
            proxies = [
                e for e in (v1_reg.get("entries") or []) if e.get("classification") == "unverified_3p_hosted_proxy"
            ]
            unique_hosts = sorted({d for e in proxies for d in (e.get("remote_domains") or [])})
            summary = (
                f"Third-party hosted remote MCP servers listed in the Official MCP Registry matching "
                f"'{target.brand}' declare external remote endpoint domains ({', '.join(unique_hosts[:5])}) "
                f"not domain-anchored to {target.domain}, introducing unverified third-party intermediation "
                f"boundaries if adopted by users or agents."
            )

        findings_objs.append(
            Finding(
                rule_id=rid,
                vector=str(fdict.get("vector") or defn.get("vector") or ""),
                axis=axis_for(rid),
                label=label,
                severity=str(fdict.get("severity") or defn.get("default_severity") or "info"),
                title=title,
                summary=summary,
                owasp=owasp_refs,
                evidence=ev_objs,
                recommendation=contextualize_recommendation(rid, v1_data, default_rec),
            )
        )

    score = score_audit(target, findings_objs, v1_data, v2_data, v3_data)
    updated = dict(report_dict)
    updated["schema_version"] = "2.0"
    updated["score"] = score.to_dict()
    updated["findings"] = [f.to_dict() for f in sort_findings(findings_objs)]
    return updated
