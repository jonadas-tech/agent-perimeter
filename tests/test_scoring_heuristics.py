"""Boundary and tier tests for the 2-axis scoring heuristics in scoring.py."""

from __future__ import annotations

import pytest

from agentic_perimeter.models import BrandTarget
from agentic_perimeter.scoring import (
    action_posture_for,
    control_posture_grade_for,
    score_audit,
    threat_pressure_level_for,
)

TARGET = BrandTarget(domain="demo.example", brand="demo")


def _v1(
    official: int = 0,
    proxies: int = 0,
    tokens: int = 0,
    reg_pkg_entries: int = 0,
    npm_unverified: int = 0,
    npm_free: int = 0,
    footprint: bool = False,
) -> dict:
    return {
        "mcp_registry": {
            "official_count": official,
            "unverified_3p_hosted_proxy_count": proxies,
            "url_path_token_exposed_count": tokens,
            "unverified_3p_package_entry_count": reg_pkg_entries,
            "entries": [],
        },
        "npm": {"official_count": 0, "unverified_count": npm_unverified, "free_email_unverified_count": npm_free, "packages": []},
        "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"has_any_mcp_footprint": footprint},
    }


def _v2(**flags: object) -> dict:
    base = {
        "live_mcp_endpoint_count": 0,
        "rfc9728_present_count": 0,
        "missing_rfc9728_count": 0,
        "broad_oauth_scope_detected": False,
        "cross_domain_drift_detected": False,
        "cross_domain_3p_delegation_detected": False,
        "apex_dnssec_enabled": False,
        "dns_aid_present": False,
    }
    base.update(flags)
    return {"root_well_known": {}, "subdomains": [], "flags": base}


def _v3() -> dict:
    return {"flags": {}}


def _control(summary, cid: str) -> dict:
    return next(c for c in summary.control_breakdown if c["id"] == cid)


def _threat(summary, tid: str) -> dict:
    return next(t for t in summary.threat_breakdown if t["id"] == tid)


@pytest.mark.parametrize(
    "score,grade",
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (55, "C"), (54, "D"), (35, "D"), (34, "F"), (0, "F"), (None, "N/A")],
)
def test_control_posture_grade_boundaries(score, grade) -> None:
    assert control_posture_grade_for(score)[0] == grade


@pytest.mark.parametrize(
    "score,level",
    [(100, "Critical"), (75, "Critical"), (74, "High"), (50, "High"), (49, "Moderate"), (25, "Moderate"), (24, "Low"), (1, "Low"), (0, "None")],
)
def test_threat_pressure_level_boundaries(score, level) -> None:
    assert threat_pressure_level_for(score) == level


@pytest.mark.parametrize(
    "grade,level,posture",
    [
        ("N/A", "None", "Baseline — Monitor"),
        ("N/A", "Low", "Baseline — Monitor"),
        ("N/A", "Moderate", "Brand Protection Alert"),
        ("N/A", "Critical", "Brand Protection Alert"),
        ("A", "Critical", "Active Defense"),
        ("B", "Moderate", "Active Monitoring"),
        ("A", "Low", "Well-Positioned"),
        ("C", "High", "Priority Hardening"),
        ("C", "Moderate", "Hardening & Monitoring"),
        ("C", "None", "Targeted Hardening"),
        ("D", "High", "Urgent Remediation"),
        ("F", "Moderate", "Action Required"),
        ("F", "Low", "Proactive Hardening"),
    ],
)
def test_action_posture_matrix(grade, level, posture) -> None:
    assert action_posture_for(grade, level, "demo.example")[0] == posture


def test_no_footprint_stays_ungraded_even_with_dnssec() -> None:
    s = score_audit(TARGET, [], _v1(), _v2(apex_dnssec_enabled=True), _v3())
    assert s.control_posture_applicable is False
    assert s.control_posture_score is None
    assert _control(s, "C6")["status"] == "baseline"


@pytest.mark.parametrize("proxies,points", [(0, 0), (1, 20), (2, 20), (3, 26), (9, 26), (10, 32)])
def test_t2_proxy_tiers(proxies, points) -> None:
    s = score_audit(TARGET, [], _v1(proxies=proxies, footprint=True), _v2(), _v3())
    assert _threat(s, "T2")["points"] == points


def test_t2_package_only_registry_entries_score_lower_than_hosted_proxies() -> None:
    s = score_audit(TARGET, [], _v1(reg_pkg_entries=2, footprint=True), _v2(), _v3())
    assert _threat(s, "T2")["points"] == 6


@pytest.mark.parametrize("free,points", [(0, 0), (1, 14), (3, 18), (10, 22)])
def test_t3_free_email_tiers(free, points) -> None:
    s = score_audit(TARGET, [], _v1(npm_unverified=max(free, 1), npm_free=free, footprint=True), _v2(), _v3())
    assert _threat(s, "T3")["points"] == points


@pytest.mark.parametrize("unverified,points", [(1, 6), (4, 6), (5, 9), (14, 9), (15, 12)])
def test_t4_unverified_package_tiers(unverified, points) -> None:
    s = score_audit(TARGET, [], _v1(npm_unverified=unverified, footprint=True), _v2(), _v3())
    assert _threat(s, "T4")["points"] == points


def test_threat_pressure_is_capped_at_100() -> None:
    v3 = {
        "active_agent_endpoints": [{"domain": "a"}],
        "phishing_flagged": [{"domain": "b"}],
        "flags": {"has_active_lookalike_agent_endpoint": True, "has_active_phishing_lookalike": True},
    }
    s = score_audit(TARGET, [], _v1(proxies=10, tokens=1, npm_unverified=20, npm_free=10, footprint=True), _v2(), v3)
    assert s.threat_pressure_score == 100
    assert s.threat_pressure_level == "Critical"


def test_c3_rfc9728_coverage_is_proportional() -> None:
    s = score_audit(TARGET, [], _v1(footprint=True), _v2(live_mcp_endpoint_count=4, rfc9728_present_count=3, missing_rfc9728_count=1), _v3())
    c3 = _control(s, "C3")
    assert c3["earned"] == 15
    assert c3["status"] == "partial"


def test_c4_broad_scopes_cap_points_even_with_full_coverage() -> None:
    s = score_audit(TARGET, [], _v1(footprint=True), _v2(live_mcp_endpoint_count=1, rfc9728_present_count=1, broad_oauth_scope_detected=True), _v3())
    assert _control(s, "C4")["earned"] == 3


def test_c4_is_a_gap_when_no_endpoint_publishes_rfc9728() -> None:
    s = score_audit(TARGET, [], _v1(footprint=True), _v2(live_mcp_endpoint_count=2, missing_rfc9728_count=2), _v3())
    assert _control(s, "C4")["earned"] == 0
    assert _control(s, "C4")["status"] == "gap"


def test_c5_third_party_delegation_beats_sibling_drift() -> None:
    s_3p = score_audit(TARGET, [], _v1(footprint=True), _v2(live_mcp_endpoint_count=1, cross_domain_3p_delegation_detected=True, cross_domain_drift_detected=True), _v3())
    s_sib = score_audit(TARGET, [], _v1(footprint=True), _v2(live_mcp_endpoint_count=1, cross_domain_drift_detected=True), _v3())
    assert _control(s_3p, "C5")["earned"] == 0
    assert _control(s_sib, "C5")["earned"] == 5


def test_c6_dns_aid_points_require_integrity() -> None:
    ok = score_audit(TARGET, [], _v1(footprint=True), _v2(apex_dnssec_enabled=True, dns_aid_present=True), _v3())
    bad = score_audit(
        TARGET, [], _v1(footprint=True),
        _v2(apex_dnssec_enabled=True, dns_aid_present=True, dns_aid_card_hash_mismatch_count=1), _v3(),
    )
    assert _control(ok, "C6")["earned"] == 12
    assert _control(bad, "C6")["earned"] == 8


def test_c1_official_registry_entry_is_all_or_nothing() -> None:
    with_entry = score_audit(TARGET, [], _v1(official=1, footprint=True), _v2(), _v3())
    without = score_audit(TARGET, [], _v1(proxies=1, footprint=True), _v2(), _v3())
    assert _control(with_entry, "C1")["earned"] == 35
    assert _control(without, "C1")["earned"] == 0
