"""Longitudinal cohort diff engine (`agent-perimeter trend`) for multi-quarter
index tracking (e.g., 2026-Q4 -> 2027-Q1).

Supports BOTH:
  - Raw `audit_batch` JSON files (`{"reports": [...]}`)
  - Anonymized study JSON files from `anonymize_batch_results` (`{"anonymized_records": [...]}`)
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from . import __version__


def _pct(num: int, den: int) -> float:
    return round((num / den) * 100.0, 1) if den > 0 else 0.0


def _round_delta(curr: Optional[float], prev: Optional[float]) -> Optional[float]:
    if curr is None or prev is None:
        return None
    return round(float(curr) - float(prev), 1)


def _mean(vals: List[int]) -> Optional[float]:
    if not vals:
        return None
    return round(sum(vals) / len(vals), 1)


def _median(vals: List[int]) -> Optional[float]:
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    if n % 2 == 1:
        return float(s[n // 2])
    return round((s[n // 2 - 1] + s[n // 2]) / 2.0, 1)


def _detect_format(payload: Dict[str, Any]) -> str:
    if isinstance(payload.get("reports"), list):
        return "raw_batch"
    if isinstance(payload.get("anonymized_records"), list):
        return "anonymized_study"
    raise ValueError(
        "Unrecognized cohort JSON format: expected 'reports' (raw batch) or 'anonymized_records' (anonymized study)."
    )


def _extract_window(payload: Dict[str, Any], fmt: str) -> Dict[str, Any]:
    if fmt == "anonymized_study":
        win = payload.get("scanned_window") or {}
        return {
            "started_at": win.get("started_at"),
            "finished_at": win.get("finished_at"),
            "tool_version": payload.get("tool_version"),
        }
    return {
        "started_at": payload.get("started_at"),
        "finished_at": payload.get("finished_at"),
        "tool_version": payload.get("tool_version"),
    }


def _infer_label(payload: Dict[str, Any], fmt: str, fallback: str) -> str:
    win = _extract_window(payload, fmt)
    ts = str(win.get("started_at") or win.get("finished_at") or "")
    if len(ts) >= 10:
        return ts[:10]
    return fallback


def _extract_dane_ans_from_raw(rep: Dict[str, Any]) -> Tuple[bool, bool, bool]:
    """Extract (dane_tlsa_present, ans_badge_present, ans_badge_spoofed) from raw report."""
    v2 = rep.get("vector2") or {}
    v2_flags = v2.get("flags") or {}
    linter = v2.get("dns_aid_linter") or {}
    v3 = rep.get("vector3") or {}
    v3_flags = v3.get("flags") or {}

    agent_recs = linter.get("agent_records") or []
    dane_present = bool(
        v2_flags.get("dane_tlsa_present")
        or bool(linter.get("dane_tlsa_hosts"))
        or any(
            isinstance(r, dict) and bool((r.get("dane_tlsa") or {}).get("present"))
            for r in agent_recs
        )
    )

    ans_present = bool(
        v2_flags.get("ans_badge_present")
        or bool(linter.get("ans_badge_verified_hosts"))
        or bool(linter.get("spoofed_ans_badge_hosts"))
        or any(
            isinstance(r, dict) and bool((r.get("ans_badge") or {}).get("present"))
            for r in agent_recs
        )
    )

    ans_spoofed = bool(
        int(v2_flags.get("spoofed_ans_badge_count") or 0) > 0
        or bool(linter.get("spoofed_ans_badge_hosts"))
        or bool(v3_flags.get("has_spoofed_ans_badge_lookalike"))
        or bool(v3.get("spoofed_ans_badge_hosts"))
        or any(
            isinstance(r, dict)
            and (
                bool((r.get("ans_badge") or {}).get("spoofed"))
                or (r.get("ans_badge") or {}).get("host_binding_status") == "host_mismatch"
            )
            for r in agent_recs
        )
    )
    return dane_present, ans_present, ans_spoofed


def _normalize_records(payload: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    fmt = _detect_format(payload)
    records: List[Dict[str, Any]] = []

    if fmt == "raw_batch":
        for idx, rep in enumerate(payload.get("reports") or []):
            if not isinstance(rep, dict):
                continue
            target = rep.get("target") or {}
            rec_id = str(target.get("domain") or f"target-{idx + 1}").strip().lower()
            score = rep.get("score") or {}
            v1 = rep.get("vector1") or {}
            v1_reg = v1.get("mcp_registry") or {}
            v1_npm = v1.get("npm") or {}
            v1_pypi = v1.get("pypi") or {}
            v1_flags = v1.get("flags") or {}
            v2 = rep.get("vector2") or {}
            v2_flags = v2.get("flags") or {}
            v3 = rep.get("vector3") or {}
            v3_flags = v3.get("flags") or {}

            dane_present, ans_present, ans_spoofed = _extract_dane_ans_from_raw(rep)
            live_cnt = int(v2_flags.get("live_mcp_endpoint_count") or 0)
            rfc_present_cnt = int(v2_flags.get("rfc9728_present_count") or 0)
            rfc_missing_cnt = int(v2_flags.get("missing_rfc9728_count") or 0)
            proxy_cnt = int(v1_reg.get("unverified_3p_hosted_proxy_count") or 0)

            posture_app = bool(score.get("control_posture_applicable", False))
            posture_score = (
                int(score["control_posture_score"])
                if posture_app and score.get("control_posture_score") is not None
                else None
            )

            records.append(
                {
                    "id": rec_id,
                    "cohort": str(target.get("cohort") or "custom"),
                    "sector": str(target.get("sector") or "Unknown"),
                    "control_posture_applicable": posture_app,
                    "control_posture_score": posture_score,
                    "control_posture_grade": str(score.get("control_posture_grade") or "N/A"),
                    "threat_pressure_score": int(score.get("threat_pressure_score") or 0),
                    "threat_pressure_level": str(score.get("threat_pressure_level") or "None"),
                    "action_posture": str(score.get("action_posture") or "Baseline — Monitor"),
                    "metrics": {
                        "has_any_mcp_footprint": bool(v1_flags.get("has_any_mcp_footprint")),
                        "official_mcp_registry_present": int(v1_reg.get("official_count") or 0) > 0,
                        "official_registry_vacuum": bool(v1_flags.get("official_registry_vacuum")),
                        "unverified_3p_hosted_proxy": proxy_cnt > 0,
                        "unverified_3p_hosted_proxy_count": proxy_cnt,
                        "url_path_token_exposure": int(v1_reg.get("url_path_token_exposed_count") or 0) > 0,
                        "unverified_npm_or_pypi_package": (
                            int(v1_npm.get("unverified_count") or 0) + int(v1_pypi.get("unverified_count") or 0)
                        ) > 0,
                        "free_email_maintainer_collision": (
                            int(v1_npm.get("free_email_unverified_count") or 0)
                            + int(v1_pypi.get("free_email_unverified_count") or 0)
                        ) > 0,
                        "live_first_party_mcp_endpoint": live_cnt > 0,
                        "rfc9728_present": rfc_present_cnt > 0,
                        "missing_rfc9728": rfc_missing_cnt > 0,
                        "apex_dnssec_enabled": bool(v2_flags.get("apex_dnssec_enabled")),
                        "dns_aid_present": bool(v2_flags.get("dns_aid_present")),
                        "dane_tlsa_present": dane_present,
                        "ans_badge_present": ans_present,
                        "ans_badge_spoofed": ans_spoofed,
                        "active_lookalike_agent_endpoint": bool(v3_flags.get("has_active_lookalike_agent_endpoint")),
                        "active_phishing_lookalike": bool(v3_flags.get("has_active_phishing_lookalike")),
                    },
                }
            )
    else:
        for idx, rec in enumerate(payload.get("anonymized_records") or []):
            if not isinstance(rec, dict):
                continue
            m = rec.get("metrics") or {}
            rec_id = str(rec.get("anon_id") or f"ANON-{idx + 1:03d}")
            live_cnt = int(m.get("live_mcp_endpoint_count") or 0)
            rfc_present_cnt = int(m.get("rfc9728_present_count") or 0)
            rfc_missing_cnt = int(m.get("missing_rfc9728_count") or 0)
            proxy_cnt = int(m.get("unverified_3p_hosted_proxy_count") or 0)

            posture_app = bool(rec.get("control_posture_applicable", False))
            posture_score = (
                int(rec["control_posture_score"])
                if posture_app and rec.get("control_posture_score") is not None
                else None
            )

            records.append(
                {
                    "id": rec_id,
                    "cohort": str(rec.get("cohort") or "custom"),
                    "sector": str(rec.get("sector") or "Unknown"),
                    "control_posture_applicable": posture_app,
                    "control_posture_score": posture_score,
                    "control_posture_grade": str(rec.get("control_posture_grade") or "N/A"),
                    "threat_pressure_score": int(rec.get("threat_pressure_score") or 0),
                    "threat_pressure_level": str(rec.get("threat_pressure_level") or "None"),
                    "action_posture": str(rec.get("action_posture") or "Baseline — Monitor"),
                    "metrics": {
                        "has_any_mcp_footprint": bool(m.get("has_any_mcp_footprint")),
                        "official_mcp_registry_present": int(m.get("official_mcp_registry_count") or 0) > 0,
                        "official_registry_vacuum": bool(m.get("official_registry_vacuum")),
                        "unverified_3p_hosted_proxy": proxy_cnt > 0,
                        "unverified_3p_hosted_proxy_count": proxy_cnt,
                        "url_path_token_exposure": int(m.get("url_path_token_exposed_count") or 0) > 0,
                        "unverified_npm_or_pypi_package": (
                            int(m.get("npm_unverified_count") or 0) + int(m.get("pypi_unverified_count") or 0)
                        ) > 0,
                        "free_email_maintainer_collision": (
                            int(m.get("npm_free_email_unverified_count") or 0)
                            + int(m.get("pypi_free_email_unverified_count") or 0)
                        ) > 0,
                        "live_first_party_mcp_endpoint": live_cnt > 0,
                        "rfc9728_present": rfc_present_cnt > 0,
                        "missing_rfc9728": rfc_missing_cnt > 0,
                        "apex_dnssec_enabled": bool(m.get("apex_dnssec_enabled")),
                        "dns_aid_present": bool(m.get("dns_aid_present")),
                        "dane_tlsa_present": bool(m.get("dane_tlsa_present")),
                        "ans_badge_present": bool(m.get("ans_badge_present")),
                        "ans_badge_spoofed": bool(m.get("ans_badge_spoofed")),
                        "active_lookalike_agent_endpoint": bool(m.get("active_lookalike_agent_endpoint")),
                        "active_phishing_lookalike": bool(m.get("active_phishing_lookalike")),
                    },
                }
            )

    return fmt, records


def _summarize_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(records)
    graded_scores = [int(r["control_posture_score"]) for r in records if r["control_posture_score"] is not None]
    threat_scores = [int(r["threat_pressure_score"]) for r in records]
    grades = Counter(r["control_posture_grade"] for r in records)
    threats = Counter(r["threat_pressure_level"] for r in records)
    actions = Counter(r["action_posture"] for r in records)

    def _cnt(key: str) -> int:
        return sum(1 for r in records if r["metrics"].get(key))

    live_mcp_n = _cnt("live_first_party_mcp_endpoint")
    total_3p_proxies = sum(int(r["metrics"].get("unverified_3p_hosted_proxy_count") or 0) for r in records)

    return {
        "count": n,
        "graded_posture_count": len(graded_scores),
        "baseline_na_count": n - len(graded_scores),
        "mean_control_posture": _mean(graded_scores),
        "median_control_posture": _median(graded_scores),
        "mean_threat_pressure": _mean(threat_scores) or 0.0,
        "median_threat_pressure": _median(threat_scores) or 0.0,
        "grade_dist": {g: grades.get(g, 0) for g in ("A", "B", "C", "D", "F", "N/A")},
        "threat_dist": {lvl: threats.get(lvl, 0) for lvl in ("Critical", "High", "Moderate", "Low", "None")},
        "action_dist": dict(actions),
        "total_3p_proxy_instances": total_3p_proxies,
        "live_mcp_count": live_mcp_n,
        "metric_counts": {
            "has_any_mcp_footprint": (_cnt("has_any_mcp_footprint"), n),
            "official_mcp_registry_present": (_cnt("official_mcp_registry_present"), n),
            "official_registry_vacuum": (_cnt("official_registry_vacuum"), n),
            "unverified_3p_hosted_proxy": (_cnt("unverified_3p_hosted_proxy"), n),
            "url_path_token_exposure": (_cnt("url_path_token_exposure"), n),
            "unverified_npm_or_pypi_package": (_cnt("unverified_npm_or_pypi_package"), n),
            "free_email_maintainer_collision": (_cnt("free_email_maintainer_collision"), n),
            "live_first_party_mcp_endpoint": (live_mcp_n, n),
            "rfc9728_coverage_among_live_mcp": (
                sum(
                    1
                    for r in records
                    if r["metrics"].get("live_first_party_mcp_endpoint") and r["metrics"].get("rfc9728_present")
                ),
                live_mcp_n,
            ),
            "missing_rfc9728_among_live_mcp": (
                sum(
                    1
                    for r in records
                    if r["metrics"].get("live_first_party_mcp_endpoint") and r["metrics"].get("missing_rfc9728")
                ),
                live_mcp_n,
            ),
            "dns_aid_present": (_cnt("dns_aid_present"), n),
            "apex_dnssec_enabled": (_cnt("apex_dnssec_enabled"), n),
            "dane_tlsa_present": (_cnt("dane_tlsa_present"), n),
            "ans_badge_present": (_cnt("ans_badge_present"), n),
            "ans_badge_spoofed": (_cnt("ans_badge_spoofed"), n),
            "active_lookalike_agent_endpoint": (_cnt("active_lookalike_agent_endpoint"), n),
            "active_phishing_lookalike": (_cnt("active_phishing_lookalike"), n),
        },
    }


_METRIC_LABELS: List[Tuple[str, str]] = [
    ("has_any_mcp_footprint", "Any external MCP footprint"),
    ("official_mcp_registry_present", "V1 Official MCP Registry anchoring"),
    ("official_registry_vacuum", "V1 Official Registry Vacuum"),
    ("unverified_3p_hosted_proxy", "V1 Unverified 3P hosted MCP proxy"),
    ("url_path_token_exposure", "V1 URL-path token exposure"),
    ("unverified_npm_or_pypi_package", "V1 Unverified npm/PyPI MCP package"),
    ("free_email_maintainer_collision", "V1 Free-email maintainer collision"),
    ("live_first_party_mcp_endpoint", "V2 Live first-party MCP endpoint"),
    ("rfc9728_coverage_among_live_mcp", "V2 RFC 9728 coverage (among live MCP)"),
    ("missing_rfc9728_among_live_mcp", "V2 Missing RFC 9728 (among live MCP)"),
    ("dns_aid_present", "V2 IETF DNS-AID records present"),
    ("apex_dnssec_enabled", "V2 Apex DNSSEC validated (AD=true)"),
    ("dane_tlsa_present", "V2 DANE TLSA present"),
    ("ans_badge_present", "V2 ANS v2 _ans-badge present"),
    ("ans_badge_spoofed", "V2/V3 Spoofed _ans-badge host mismatch"),
    ("active_lookalike_agent_endpoint", "V3 Active lookalike agent endpoint"),
    ("active_phishing_lookalike", "V3 Phishing-warning lookalike domain"),
]


def compute_trend(
    previous: Dict[str, Any],
    current: Dict[str, Any],
    label_prev: Optional[str] = None,
    label_curr: Optional[str] = None,
) -> Dict[str, Any]:
    """Compute longitudinal cohort deltas between two batch or anonymized study JSONs."""
    fmt_prev, recs_prev = _normalize_records(previous)
    fmt_curr, recs_curr = _normalize_records(current)

    prev_map = {r["id"]: r for r in recs_prev}
    curr_map = {r["id"]: r for r in recs_curr}
    prev_ids = set(prev_map.keys())
    curr_ids = set(curr_map.keys())

    matched_ids = sorted(prev_ids & curr_ids)
    added_ids = sorted(curr_ids - prev_ids)
    removed_ids = sorted(prev_ids - curr_ids)

    sum_prev = _summarize_records(recs_prev)
    sum_curr = _summarize_records(recs_curr)

    deltas: Dict[str, Dict[str, Any]] = {}
    for key, label in _METRIC_LABELS:
        p_cnt, p_den = sum_prev["metric_counts"][key]
        c_cnt, c_den = sum_curr["metric_counts"][key]
        p_pct = _pct(p_cnt, p_den)
        c_pct = _pct(c_cnt, c_den)
        deltas[key] = {
            "label": label,
            "previous_count": p_cnt,
            "previous_denominator": p_den,
            "previous_pct": p_pct,
            "current_count": c_cnt,
            "current_denominator": c_den,
            "current_pct": c_pct,
            "count_delta": c_cnt - p_cnt,
            "pct_point_delta": round(c_pct - p_pct, 1),
        }

    # Distribution shifts
    grade_shift = {
        g: {
            "previous": sum_prev["grade_dist"][g],
            "current": sum_curr["grade_dist"][g],
            "delta": sum_curr["grade_dist"][g] - sum_prev["grade_dist"][g],
        }
        for g in ("A", "B", "C", "D", "F", "N/A")
    }
    threat_shift = {
        lvl: {
            "previous": sum_prev["threat_dist"][lvl],
            "current": sum_curr["threat_dist"][lvl],
            "delta": sum_curr["threat_dist"][lvl] - sum_prev["threat_dist"][lvl],
        }
        for lvl in ("Critical", "High", "Moderate", "Low", "None")
    }
    all_actions = sorted(set(sum_prev["action_dist"].keys()) | set(sum_curr["action_dist"].keys()))
    action_shift = {
        ap: {
            "previous": sum_prev["action_dist"].get(ap, 0),
            "current": sum_curr["action_dist"].get(ap, 0),
            "delta": sum_curr["action_dist"].get(ap, 0) - sum_prev["action_dist"].get(ap, 0),
        }
        for ap in all_actions
    }

    # Matched target movers (improved vs regressed)
    improved_targets: List[Dict[str, Any]] = []
    regressed_targets: List[Dict[str, Any]] = []
    unchanged_count = 0

    for tid in matched_ids:
        rp = prev_map[tid]
        rc = curr_map[tid]
        p_post = rp["control_posture_score"]
        c_post = rc["control_posture_score"]
        post_delta = (c_post - p_post) if (p_post is not None and c_post is not None) else None
        threat_delta = rc["threat_pressure_score"] - rp["threat_pressure_score"]

        # Detect newly adopted key controls even if previously N/A
        newly_anchored = (not rp["metrics"]["official_mcp_registry_present"]) and rc["metrics"]["official_mcp_registry_present"]
        lost_anchor = rp["metrics"]["official_mcp_registry_present"] and (not rc["metrics"]["official_mcp_registry_present"])

        mover = {
            "id": tid,
            "sector": rc["sector"],
            "cohort": rc["cohort"],
            "control_posture_previous": p_post,
            "control_posture_current": c_post,
            "control_posture_delta": post_delta,
            "grade_previous": rp["control_posture_grade"],
            "grade_current": rc["control_posture_grade"],
            "threat_pressure_previous": rp["threat_pressure_score"],
            "threat_pressure_current": rc["threat_pressure_score"],
            "threat_pressure_delta": threat_delta,
            "action_previous": rp["action_posture"],
            "action_current": rc["action_posture"],
        }

        is_improved = False
        is_regressed = False
        if post_delta is not None and post_delta > 0:
            is_improved = True
        elif post_delta is not None and post_delta < 0:
            is_regressed = True
        elif newly_anchored and threat_delta <= 0:
            is_improved = True
        elif lost_anchor:
            is_regressed = True
        elif threat_delta < 0:
            is_improved = True
        elif threat_delta > 0:
            is_regressed = True

        if is_improved:
            improved_targets.append(mover)
        elif is_regressed:
            regressed_targets.append(mover)
        else:
            unchanged_count += 1

    improved_targets.sort(
        key=lambda m: (
            -(m["control_posture_delta"] if m["control_posture_delta"] is not None else 0),
            m["threat_pressure_delta"],
            m["id"],
        )
    )
    regressed_targets.sort(
        key=lambda m: (
            (m["control_posture_delta"] if m["control_posture_delta"] is not None else 0),
            -m["threat_pressure_delta"],
            m["id"],
        )
    )

    # Sector-level longitudinal shifts
    all_sectors = sorted({r["sector"] for r in recs_prev} | {r["sector"] for r in recs_curr})
    sector_shifts: Dict[str, Dict[str, Any]] = {}
    improved_sectors: List[str] = []
    regressed_sectors: List[str] = []

    for sec in all_sectors:
        sp = _summarize_records([r for r in recs_prev if r["sector"] == sec])
        sc = _summarize_records([r for r in recs_curr if r["sector"] == sec])
        mp_delta = _round_delta(sc["mean_control_posture"], sp["mean_control_posture"])
        mt_delta = _round_delta(sc["mean_threat_pressure"], sp["mean_threat_pressure"])
        off_p = _pct(*sp["metric_counts"]["official_mcp_registry_present"])
        off_c = _pct(*sc["metric_counts"]["official_mcp_registry_present"])
        off_delta = round(off_c - off_p, 1)

        if (mp_delta is not None and mp_delta > 0) or (mp_delta is None and mt_delta is not None and mt_delta < 0):
            direction = "improved"
            improved_sectors.append(sec)
        elif (mp_delta is not None and mp_delta < 0) or (mp_delta is None and mt_delta is not None and mt_delta > 0):
            direction = "regressed"
            regressed_sectors.append(sec)
        else:
            direction = "stable"

        sector_shifts[sec] = {
            "previous_count": sp["count"],
            "current_count": sc["count"],
            "mean_control_posture_previous": sp["mean_control_posture"],
            "mean_control_posture_current": sc["mean_control_posture"],
            "mean_control_posture_delta": mp_delta,
            "mean_threat_pressure_previous": sp["mean_threat_pressure"],
            "mean_threat_pressure_current": sc["mean_threat_pressure"],
            "mean_threat_pressure_delta": mt_delta,
            "official_registry_pct_previous": off_p,
            "official_registry_pct_current": off_c,
            "official_registry_pct_delta": off_delta,
            "direction": direction,
        }

    lbl_prev = label_prev or _infer_label(previous, fmt_prev, "previous")
    lbl_curr = label_curr or _infer_label(current, fmt_curr, "current")

    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "input_format": fmt_prev if fmt_prev == fmt_curr else f"{fmt_prev}_to_{fmt_curr}",
        "labels": {"previous": lbl_prev, "current": lbl_curr},
        "windows": {
            "previous": _extract_window(previous, fmt_prev),
            "current": _extract_window(current, fmt_curr),
        },
        "cohort_overlap": {
            "previous_total": len(recs_prev),
            "current_total": len(recs_curr),
            "matched_count": len(matched_ids),
            "matched_targets": matched_ids,
            "added_count": len(added_ids),
            "added_targets": added_ids,
            "removed_count": len(removed_ids),
            "removed_targets": removed_ids,
        },
        "total_3p_proxy_instances": {
            "previous": sum_prev["total_3p_proxy_instances"],
            "current": sum_curr["total_3p_proxy_instances"],
            "delta": sum_curr["total_3p_proxy_instances"] - sum_prev["total_3p_proxy_instances"],
        },
        "adoption_and_exposure_deltas": deltas,
        "posture_and_threat_shifts": {
            "graded_posture_count": {
                "previous": sum_prev["graded_posture_count"],
                "current": sum_curr["graded_posture_count"],
                "delta": sum_curr["graded_posture_count"] - sum_prev["graded_posture_count"],
            },
            "mean_control_posture": {
                "previous": sum_prev["mean_control_posture"],
                "current": sum_curr["mean_control_posture"],
                "delta": _round_delta(sum_curr["mean_control_posture"], sum_prev["mean_control_posture"]),
            },
            "median_control_posture": {
                "previous": sum_prev["median_control_posture"],
                "current": sum_curr["median_control_posture"],
                "delta": _round_delta(sum_curr["median_control_posture"], sum_prev["median_control_posture"]),
            },
            "mean_threat_pressure": {
                "previous": sum_prev["mean_threat_pressure"],
                "current": sum_curr["mean_threat_pressure"],
                "delta": _round_delta(sum_curr["mean_threat_pressure"], sum_prev["mean_threat_pressure"]),
            },
            "median_threat_pressure": {
                "previous": sum_prev["median_threat_pressure"],
                "current": sum_curr["median_threat_pressure"],
                "delta": _round_delta(sum_curr["median_threat_pressure"], sum_prev["median_threat_pressure"]),
            },
            "control_posture_grade_shift": grade_shift,
            "threat_pressure_level_shift": threat_shift,
            "action_posture_shift": action_shift,
        },
        "target_movers": {
            "improved_count": len(improved_targets),
            "regressed_count": len(regressed_targets),
            "unchanged_count": unchanged_count,
            "improved": improved_targets,
            "regressed": regressed_targets,
        },
        "sector_shifts": sector_shifts,
        "improved_sectors": improved_sectors,
        "regressed_sectors": regressed_sectors,
    }


def _fmt_signed(val: Optional[float | int], suffix: str = "") -> str:
    if val is None:
        return "N/A"
    if isinstance(val, int):
        sign = "+" if val > 0 else ""
        return f"{sign}{val}{suffix}"
    sign = "+" if val > 0 else ""
    return f"{sign}{val:.1f}{suffix}"


def _fmt_opt(val: Optional[float | int]) -> str:
    return "N/A" if val is None else str(val)


def render_trend_markdown(trend: Dict[str, Any]) -> str:
    """Render a crisp publication-grade Markdown longitudinal cohort trend report."""
    labels = trend.get("labels") or {}
    lp = str(labels.get("previous") or "previous")
    lc = str(labels.get("current") or "current")
    ov = trend.get("cohort_overlap") or {}
    shifts = trend.get("posture_and_threat_shifts") or {}
    proxies = trend.get("total_3p_proxy_instances") or {}
    deltas = trend.get("adoption_and_exposure_deltas") or {}
    movers = trend.get("target_movers") or {}
    sectors = trend.get("sector_shifts") or {}

    lines: List[str] = [
        f"# External Agentic Exposure Longitudinal Trend: {lp} -> {lc}",
        "",
        f"**Input Format:** `{trend.get('input_format')}` · **Tool:** `agent-perimeter` v{trend.get('tool_version')}  ",
        f"**Cohort Overlap:** `{ov.get('previous_total', 0)}` ({lp}) -> `{ov.get('current_total', 0)}` ({lc}) | "
        f"Matched: `{ov.get('matched_count', 0)}` | Added: `{ov.get('added_count', 0)}` | Removed: `{ov.get('removed_count', 0)}`  ",
        f"**Total 3rd-Party Hosted MCP Proxy Instances:** `{proxies.get('previous', 0)}` -> `{proxies.get('current', 0)}` "
        f"(`{_fmt_signed(proxies.get('delta', 0))}`)",
        "",
        "## 1. Adoption & Exposure Metric Deltas",
        "",
        f"| Metric | {lp} | {lc} | Count Delta | Pct-Point Delta |",
        "|---|---:|---:|---:|---:|",
    ]

    for key, _ in _METRIC_LABELS:
        d = deltas.get(key)
        if not d:
            continue
        p_cell = f"{d['previous_count']}/{d['previous_denominator']} ({d['previous_pct']}%)"
        c_cell = f"{d['current_count']}/{d['current_denominator']} ({d['current_pct']}%)"
        lines.append(
            f"| {d['label']} | {p_cell} | {c_cell} | {_fmt_signed(d['count_delta'])} | {_fmt_signed(d['pct_point_delta'], ' pp')} |"
        )

    mp = shifts.get("mean_control_posture") or {}
    medp = shifts.get("median_control_posture") or {}
    mt = shifts.get("mean_threat_pressure") or {}
    medt = shifts.get("median_threat_pressure") or {}

    lines.extend(
        [
            "",
            "## 2. 2-Axis Control Posture & Threat Pressure Shifts",
            "",
            f"- **Mean First-Party Control Posture (Graded):** `{_fmt_opt(mp.get('previous'))}` -> `{_fmt_opt(mp.get('current'))}` (`{_fmt_signed(mp.get('delta'))}`)",
            f"- **Median First-Party Control Posture (Graded):** `{_fmt_opt(medp.get('previous'))}` -> `{_fmt_opt(medp.get('current'))}` (`{_fmt_signed(medp.get('delta'))}`)",
            f"- **Mean External Threat Pressure:** `{_fmt_opt(mt.get('previous'))}` -> `{_fmt_opt(mt.get('current'))}` (`{_fmt_signed(mt.get('delta'))}`)",
            f"- **Median External Threat Pressure:** `{_fmt_opt(medt.get('previous'))}` -> `{_fmt_opt(medt.get('current'))}` (`{_fmt_signed(medt.get('delta'))}`)",
            "",
            "### Control Posture Grade Distribution",
            "",
            f"| Grade | {lp} | {lc} | Delta |",
            "|---|---:|---:|---:|",
        ]
    )
    for g in ("A", "B", "C", "D", "F", "N/A"):
        gs = (shifts.get("control_posture_grade_shift") or {}).get(g) or {}
        lines.append(
            f"| {g} | {gs.get('previous', 0)} | {gs.get('current', 0)} | {_fmt_signed(gs.get('delta', 0))} |"
        )

    lines.extend(
        [
            "",
            "### External Threat Pressure Level Distribution",
            "",
            f"| Level | {lp} | {lc} | Delta |",
            "|---|---:|---:|---:|",
        ]
    )
    for lvl in ("Critical", "High", "Moderate", "Low", "None"):
        ts = (shifts.get("threat_pressure_level_shift") or {}).get(lvl) or {}
        lines.append(
            f"| {lvl} | {ts.get('previous', 0)} | {ts.get('current', 0)} | {_fmt_signed(ts.get('delta', 0))} |"
        )

    lines.extend(
        [
            "",
            f"## 3. Matched Target Movers (Improved: {movers.get('improved_count', 0)} | Regressed: {movers.get('regressed_count', 0)} | Unchanged: {movers.get('unchanged_count', 0)})",
            "",
        ]
    )
    improved = movers.get("improved") or []
    if improved:
        lines.extend(
            [
                "### Top Improved Targets",
                "",
                "| Target | Sector | Control Posture | Threat Pressure | Action Posture |",
                "|---|---|---:|---:|---|",
            ]
        )
        for m in improved[:15]:
            p_str = f"{_fmt_opt(m['control_posture_previous'])} ({m['grade_previous']}) -> {_fmt_opt(m['control_posture_current'])} ({m['grade_current']})"
            t_str = f"{m['threat_pressure_previous']} -> {m['threat_pressure_current']} ({_fmt_signed(m['threat_pressure_delta'])})"
            lines.append(
                f"| `{m['id']}` | {m['sector']} | {p_str} | {t_str} | {m['action_previous']} -> {m['action_current']} |"
            )
        lines.append("")

    regressed = movers.get("regressed") or []
    if regressed:
        lines.extend(
            [
                "### Top Regressed Targets",
                "",
                "| Target | Sector | Control Posture | Threat Pressure | Action Posture |",
                "|---|---|---:|---:|---|",
            ]
        )
        for m in regressed[:15]:
            p_str = f"{_fmt_opt(m['control_posture_previous'])} ({m['grade_previous']}) -> {_fmt_opt(m['control_posture_current'])} ({m['grade_current']})"
            t_str = f"{m['threat_pressure_previous']} -> {m['threat_pressure_current']} ({_fmt_signed(m['threat_pressure_delta'])})"
            lines.append(
                f"| `{m['id']}` | {m['sector']} | {p_str} | {t_str} | {m['action_previous']} -> {m['action_current']} |"
            )
        lines.append("")

    if sectors:
        lines.extend(
            [
                "## 4. Sector Shifts",
                "",
                f"| Sector | Targets ({lp} -> {lc}) | Mean Posture Delta | Mean Threat Delta | Official Registry Delta | Direction |",
                "|---|---:|---:|---:|---:|---|",
            ]
        )
        for sec, sdata in sorted(sectors.items()):
            lines.append(
                f"| {sec} | {sdata['previous_count']} -> {sdata['current_count']} | "
                f"{_fmt_signed(sdata['mean_control_posture_delta'])} | "
                f"{_fmt_signed(sdata['mean_threat_pressure_delta'])} | "
                f"{_fmt_signed(sdata['official_registry_pct_delta'], ' pp')} | "
                f"{sdata['direction']} |"
            )
        lines.append("")

    return "\n".join(lines)
