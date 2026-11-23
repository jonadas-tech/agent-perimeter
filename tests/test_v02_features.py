"""Unit tests for v0.2.0 features: SARIF 2.1.0 export, baseline diff/CI gating, and passive in-memory static audit."""

from __future__ import annotations

import json
from pathlib import Path

from agent_perimeter import cli
from agent_perimeter.diff import compare_reports, format_diff_summary
from agent_perimeter.models import AuditReport, BrandTarget, Evidence, Finding, ScoreSummary
from agent_perimeter.sarif import render_sarif
from agent_perimeter.static_audit import _inspect_text_files
from agent_perimeter.taxonomy import owasp_list_for


def _make_sample_report(domain: str = "acme.example", include_proxy: bool = True) -> dict:
    findings = []
    entries = []
    if include_proxy:
        findings.append(
            Finding(
                rule_id="v1_unverified_3p_hosted_proxy",
                vector="V1",
                axis="external_threat",
                label="Unverified 3rd-Party Hosted Proxy",
                severity="high",
                title="1 unverified 3rd-party hosted MCP proxy",
                summary="Third-party hosted remote MCP server claims brand.",
                owasp=owasp_list_for("v1_unverified_3p_hosted_proxy"),
                evidence=[
                    Evidence(
                        source="mcp_registry",
                        locator="https://proxy.thirdparty.example/mcp",
                        detail="Registry entry routes externally",
                        raw={"name": "example.thirdparty/acme"},
                    )
                ],
                recommendation="Enforce first-party MCP allowlist.",
            )
        )
        entries.append({"name": "example.thirdparty/acme", "classification": "unverified_3p_hosted_proxy"})

    sc = ScoreSummary(
        scoring_model="2-axis-v1",
        control_posture_score=85,
        control_posture_grade="B",
        control_posture_label="Strong",
        control_posture_applicable=True,
        control_breakdown=[],
        threat_pressure_score=20 if include_proxy else 0,
        threat_pressure_level="Low" if include_proxy else "None",
        threat_breakdown=[],
        action_posture="Active Monitoring" if include_proxy else "Well-Positioned",
        action_posture_summary="Summary",
        counts_by_severity={"critical": 0, "high": 1 if include_proxy else 0, "medium": 0, "low": 0, "info": 0},
        counts_by_vector={"V1": 1 if include_proxy else 0, "V2": 0, "V3": 0},
        counts_by_axis={"first_party_control": 0, "external_threat": 1 if include_proxy else 0},
        ciso_takeaways=["Takeaway"],
        first_party_priorities=[],
        external_defense_priorities=[],
        top_priorities=[],
    )
    rep = AuditReport(
        schema_version="2.0",
        tool_version="0.2.0",
        scanned_at="2026-11-23T12:00:00Z",
        duration_seconds=1.2,
        target=BrandTarget(domain=domain, brand="acme"),
        verified_sibling_domains=[domain],
        score=sc,
        findings=findings,
        vector1={
            "mcp_registry": {"official_count": 1, "unverified_3p_hosted_proxy_count": len(entries), "url_path_token_exposed_count": 0, "entries": entries},
            "npm": {"packages": []},
            "pypi": {"packages": []},
            "flags": {},
        },
        vector2={"dns_aid": {"apex_dnssec_ad": True, "dns_aid_present": False}, "subdomains": [], "flags": {"live_mcp_endpoint_count": 0, "rfc9728_present_count": 0, "dns_aid_present": False, "apex_dnssec_enabled": True}},
        vector3={"permutations_tested": 6, "active_agent_endpoints": [], "phishing_flagged": [], "flags": {}},
    )
    return rep.to_dict()


def test_sarif_export_structure_and_owasp_tags() -> None:
    report = _make_sample_report(include_proxy=True)
    sarif = render_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-perimeter"
    assert len(run["tool"]["driver"]["rules"]) >= 12
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "v1_unverified_3p_hosted_proxy"
    assert res["level"] == "error"
    assert "ASI04" in res["properties"]["owasp"]
    assert res["partialFingerprints"]["primaryLocationLineHash"]


def test_baseline_diff_detects_new_proxy_and_cli_fail_on_new(monkeypatch, tmp_path: Path) -> None:
    base = _make_sample_report(include_proxy=False)
    cur = _make_sample_report(include_proxy=True)
    diff = compare_reports(cur, base)
    assert diff["has_new_exposures"] is True
    assert diff["new_unverified_3p_proxies"] == ["example.thirdparty/acme"]
    assert diff["new_finding_rules"] == ["v1_unverified_3p_hosted_proxy"]
    assert any("NEW external exposure" in ln for ln in format_diff_summary(diff))

    # Verify CLI --baseline + --fail-on-new returns exit code 2 and writes SARIF
    base_file = tmp_path / "base.json"
    base_file.write_text(json.dumps(base), encoding="utf-8")
    sarif_file = tmp_path / "out.sarif"

    class _DummyReport:
        def to_dict(self):
            return cur

    monkeypatch.setattr(cli, "audit_domain", lambda **kwargs: _DummyReport())
    rc = cli.main([
        "audit", "acme.example",
        "--baseline", str(base_file),
        "--fail-on-new",
        "--sarif", str(sarif_file),
        "--quiet",
    ])
    assert rc == 2
    assert json.loads(sarif_file.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_static_in_memory_signal_extraction() -> None:
    # Unverified remote postinstall + dormant stub + unrelated CLI bin shadowing
    files = [
        ("package/index.js", "module.exports = { name: 'mcp-server-acme', version: '0.0.1', status: 'coming-soon' };"),
        ("package/scripts/install.js", "const url = 'https://github.com/u/r/releases/download/v1.0/bin.tar.gz'; fetch(url);"),
    ]
    sig = _inspect_text_files(
        files=files,
        pkg_name="acme-mcp",
        target_brand="acme",
        lifecycle_scripts={"postinstall": "node scripts/install.js"},
        bin_names=["notion"],
        repo_url="",
    )
    assert sig["dormant_placeholder_stub"] is True
    assert sig["unverified_remote_postinstall"] is True
    assert sig["unrelated_cli_bin_shadowing"] == ["notion"]
    assert sig["missing_repository_url"] is True
