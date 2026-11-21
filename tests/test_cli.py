"""CLI smoke tests for agent-perimeter."""

from __future__ import annotations

import json
from pathlib import Path

from agent_perimeter import cli
from agent_perimeter.models import AuditReport, BrandTarget, ScoreSummary


def test_cli_audit_exports_json_and_html(monkeypatch, tmp_path: Path) -> None:
    def _fake_audit_domain(**kwargs):
        t = BrandTarget(domain=kwargs["domain"], brand="demo")
        sc = ScoreSummary(
            scoring_model="2-axis-v1",
            control_posture_score=None,
            control_posture_grade="N/A",
            control_posture_label="Baseline (No Agentic Footprint)",
            control_posture_applicable=False,
            control_breakdown=[],
            threat_pressure_score=0,
            threat_pressure_level="None",
            threat_breakdown=[],
            action_posture="Baseline — Monitor",
            action_posture_summary="No external agentic footprint detected.",
            counts_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            counts_by_vector={"V1": 0, "V2": 0, "V3": 0},
            counts_by_axis={"first_party_control": 0, "external_threat": 0},
            ciso_takeaways=["Minimal external MCP footprint detected."],
            first_party_priorities=[],
            external_defense_priorities=[],
            top_priorities=["Maintain monitoring."],
        )
        return AuditReport(
            schema_version="2.0",
            tool_version="0.1.0",
            scanned_at="2026-11-21T12:00:00Z",
            duration_seconds=1.1,
            target=t,
            verified_sibling_domains=["demo.com"],
            score=sc,
            findings=[],
            vector1={"mcp_registry": {"official_count": 0, "unverified_3p_hosted_proxy_count": 0, "url_path_token_exposed_count": 0, "entries": []}, "npm": {"unverified_count": 0, "free_email_unverified_count": 0, "packages": []}, "pypi": {"unverified_count": 0, "free_email_unverified_count": 0, "packages": []}, "flags": {}},
            vector2={"dns_aid": {"apex_dnssec_ad": False, "dns_aid_present": False}, "subdomains": [], "flags": {"live_mcp_endpoint_count": 0, "rfc9728_present_count": 0, "dns_aid_present": False, "apex_dnssec_enabled": False}},
            vector3={"permutations_tested": 6, "active_agent_endpoints": [], "phishing_flagged": [], "flags": {}},
        )

    monkeypatch.setattr(cli, "audit_domain", _fake_audit_domain)
    jpath = tmp_path / "out.json"
    hpath = tmp_path / "out.html"

    rc = cli.main(["audit", "demo.com", "--json", str(jpath), "--html", str(hpath), "--quiet"])
    assert rc == 0
    parsed = json.loads(jpath.read_text(encoding="utf-8"))
    assert parsed["target"]["domain"] == "demo.com"
    assert parsed["schema_version"] == "2.0"
    assert parsed["score"]["scoring_model"] == "2-axis-v1"
    html_out = hpath.read_text(encoding="utf-8")
    assert "External Agentic Exposure Report" in html_out
    assert "Baseline Readiness" in html_out


def test_normalize_target_preserves_leading_w() -> None:
    from agent_perimeter.scanner import normalize_target

    assert normalize_target("walmart.com").domain == "walmart.com"
    assert normalize_target("wellsfargo.com").domain == "wellsfargo.com"
    assert normalize_target("workday.com").domain == "workday.com"
    assert normalize_target("www.walmart.com").domain == "walmart.com"
