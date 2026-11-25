"""Baseline diff engine for continuous passive external MCP monitoring in CI/CD."""

from __future__ import annotations

from typing import Any, Dict, List, Set


def _extract_3p_proxies(report: Dict[str, Any]) -> Set[str]:
    entries = ((report.get("vector1") or {}).get("mcp_registry") or {}).get("entries") or []
    return {
        str(e.get("name"))
        for e in entries
        if e.get("classification") == "unverified_3p_hosted_proxy" and e.get("name")
    }


def _extract_unverified_pkgs(report: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    v1 = report.get("vector1") or {}
    for p in (v1.get("npm") or {}).get("packages") or []:
        if not p.get("official_anchored") and p.get("name"):
            out.add(f"npm:{p['name']}")
    for p in (v1.get("pypi") or {}).get("packages") or []:
        if not p.get("official_anchored") and p.get("name"):
            out.add(f"pypi:{p['name']}")
    return out


def _extract_v3_alerts(report: Dict[str, Any]) -> Set[str]:
    v3 = report.get("vector3") or {}
    out: Set[str] = set()
    for item in v3.get("active_agent_endpoints") or []:
        if item.get("domain"):
            out.add(f"endpoint:{item['domain']}")
    for item in v3.get("phishing_flagged") or []:
        if item.get("domain"):
            out.add(f"phishing:{item['domain']}")
    return out


def _extract_missing_rfc9728(report: Dict[str, Any]) -> Set[str]:
    subs = (report.get("vector2") or {}).get("subdomains") or []
    return {
        str(s.get("fqdn"))
        for s in subs
        if s.get("missing_rfc9728") and s.get("fqdn")
    }


def compare_reports(current: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
    """Compare a current audit report dict against a saved JSON baseline to surface new exposures."""
    cur_rules = {str(f.get("rule_id")) for f in (current.get("findings") or []) if f.get("rule_id")}
    base_rules = {str(f.get("rule_id")) for f in (baseline.get("findings") or []) if f.get("rule_id")}

    cur_proxies = _extract_3p_proxies(current)
    base_proxies = _extract_3p_proxies(baseline)

    cur_pkgs = _extract_unverified_pkgs(current)
    base_pkgs = _extract_unverified_pkgs(baseline)

    cur_v3 = _extract_v3_alerts(current)
    base_v3 = _extract_v3_alerts(baseline)

    cur_missing_rfc = _extract_missing_rfc9728(current)
    base_missing_rfc = _extract_missing_rfc9728(baseline)

    new_rules = sorted(cur_rules - base_rules)
    resolved_rules = sorted(base_rules - cur_rules)
    new_proxies = sorted(cur_proxies - base_proxies)
    removed_proxies = sorted(base_proxies - cur_proxies)
    new_pkgs = sorted(cur_pkgs - base_pkgs)
    removed_pkgs = sorted(base_pkgs - cur_pkgs)
    new_v3 = sorted(cur_v3 - base_v3)
    new_rfc_gaps = sorted(cur_missing_rfc - base_missing_rfc)

    cur_sc = current.get("score") or {}
    base_sc = baseline.get("score") or {}
    c_posture = cur_sc.get("control_posture_score")
    b_posture = base_sc.get("control_posture_score")
    posture_delta = (
        int(c_posture) - int(b_posture)
        if (c_posture is not None and b_posture is not None)
        else None
    )
    threat_delta = int(cur_sc.get("threat_pressure_score") or 0) - int(base_sc.get("threat_pressure_score") or 0)

    has_new_exposures = bool(new_rules or new_proxies or new_pkgs or new_v3 or new_rfc_gaps)

    return {
        "baseline_scanned_at": baseline.get("scanned_at"),
        "current_scanned_at": current.get("scanned_at"),
        "has_new_exposures": has_new_exposures,
        "new_finding_rules": new_rules,
        "resolved_finding_rules": resolved_rules,
        "new_unverified_3p_proxies": new_proxies,
        "removed_unverified_3p_proxies": removed_proxies,
        "new_unverified_packages": new_pkgs,
        "removed_unverified_packages": removed_pkgs,
        "new_v3_lookalike_alerts": new_v3,
        "new_missing_rfc9728_endpoints": new_rfc_gaps,
        "control_posture_delta": posture_delta,
        "threat_pressure_delta": threat_delta,
        "action_posture_before": base_sc.get("action_posture"),
        "action_posture_after": cur_sc.get("action_posture"),
    }


def format_diff_summary(diff: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    if not diff.get("has_new_exposures"):
        lines.append("Baseline diff: no new external exposures detected.")
    else:
        lines.append("Baseline diff: NEW external exposure(s) detected:")
        if diff.get("new_finding_rules"):
            lines.append(f"  + New finding rules: {', '.join(diff['new_finding_rules'])}")
        if diff.get("new_unverified_3p_proxies"):
            lines.append(f"  + New unverified 3P proxies: {', '.join(diff['new_unverified_3p_proxies'])}")
        if diff.get("new_unverified_packages"):
            lines.append(f"  + New unverified packages: {', '.join(diff['new_unverified_packages'][:10])}")
        if diff.get("new_v3_lookalike_alerts"):
            lines.append(f"  + New V3 lookalike alerts: {', '.join(diff['new_v3_lookalike_alerts'])}")
        if diff.get("new_missing_rfc9728_endpoints"):
            lines.append(f"  + New RFC 9728 gaps: {', '.join(diff['new_missing_rfc9728_endpoints'])}")
    if diff.get("resolved_finding_rules"):
        lines.append(f"  - Resolved finding rules: {', '.join(diff['resolved_finding_rules'])}")
    return lines
