"""Tests for 2-axis scoring, OWASP taxonomy neutrality, CISO HTML report rendering, and Top-100 anonymizer."""

from __future__ import annotations

import re

from agent_perimeter.models import AuditReport, BrandTarget, Evidence, Finding
from agent_perimeter.report_html import render_html_report
from agent_perimeter.scoring import SCORING_MODEL, score_audit
from agent_perimeter.study import anonymize_batch_results, render_study_markdown
from agent_perimeter.taxonomy import FINDING_DEFINITIONS, OWASP_ASI, OWASP_MCP, owasp_list_for


def _empty_v1() -> dict:
    return {
        "mcp_registry": {
            "official_count": 0,
            "unverified_3p_hosted_proxy_count": 0,
            "url_path_token_exposed_count": 0,
            "unverified_3p_package_entry_count": 0,
            "entries": [],
        },
        "npm": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"official_registry_vacuum": False, "has_any_mcp_footprint": False},
    }


def _empty_v2(dnssec: bool = False, dns_aid: bool = False) -> dict:
    return {
        "dns_aid": {"apex_dnssec_ad": dnssec, "dns_aid_present": dns_aid},
        "root_well_known": {},
        "subdomains": [],
        "flags": {
            "live_mcp_endpoint_count": 0,
            "rfc9728_present_count": 0,
            "missing_rfc9728_count": 0,
            "broad_oauth_scope_detected": False,
            "cross_domain_drift_detected": False,
            "cross_domain_3p_delegation_detected": False,
            "apex_dnssec_enabled": dnssec,
            "dns_aid_present": dns_aid,
            "ct_provider_used": "certspotter",
        },
    }


def _empty_v3(agent_hit: bool = False, phish_hit: bool = False) -> dict:
    return {
        "permutations_tested": 6,
        "active_agent_endpoints": [{"domain": "mcp-demo.com"}] if agent_hit else [],
        "phishing_flagged": [{"domain": "demo-ai.com"}] if phish_hit else [],
        "flags": {
            "has_active_lookalike_agent_endpoint": agent_hit,
            "has_active_phishing_lookalike": phish_hit,
        },
    }


def test_owasp_canonical_titles_mece_axes_and_neutral_labels() -> None:
    assert OWASP_ASI["ASI04"].title == "Agentic Supply Chain Vulnerabilities"
    assert OWASP_ASI["ASI07"].title == "Insecure Inter-Agent Communication"
    assert OWASP_MCP["MCP04:2025"].title == "Software Supply Chain Attacks & Dependency Tampering"
    assert OWASP_MCP["MCP09:2025"].title == "Shadow MCP Servers"

    axes = {"first_party_control": 0, "external_threat": 0}
    for rule_id, defn in FINDING_DEFINITIONS.items():
        # Strict legal neutrality check: no defamatory 'malicious' label in any finding definition
        assert "malicious" not in str(defn["label"]).lower(), f"Non-neutral label in {rule_id}"
        assert defn["axis"] in axes, f"Missing/invalid axis on {rule_id}"
        axes[str(defn["axis"])] += 1

    # Strict MECE split: 6 first_party_control + 6 external_threat
    assert axes == {"first_party_control": 6, "external_threat": 6}
    assert FINDING_DEFINITIONS["v1_unscoped_free_email_collision"]["label"] == "Unverified Package / Free-Email Maintainer"
    assert FINDING_DEFINITIONS["v3_active_phishing_lookalike"]["label"] == "Phishing-Warning Lookalike Domain"


def test_two_axis_scoring_archetypes_and_context_aware_recommendations() -> None:
    # 1. Zero-footprint traditional enterprise -> N/A Baseline (no inflated Grade A!)
    t_zero = BrandTarget(domain="zero.com", brand="zero", cohort="fortune_traditional")
    s_zero = score_audit(t_zero, [], _empty_v1(), _empty_v2(dnssec=False), _empty_v3())
    assert s_zero.scoring_model == SCORING_MODEL
    assert s_zero.control_posture_applicable is False
    assert s_zero.control_posture_score is None
    assert s_zero.control_posture_grade == "N/A"
    assert s_zero.threat_pressure_score == 0
    assert s_zero.threat_pressure_level == "None"
    assert s_zero.action_posture == "Baseline — Monitor"

    # 2. CapitalOne-style: zero MCP footprint + V3 phishing-warning lookalike -> N/A + Moderate -> Brand Protection Alert
    t_cap = BrandTarget(domain="capdemo.com", brand="capdemo", cohort="fortune_traditional")
    s_cap = score_audit(t_cap, [], _empty_v1(), _empty_v2(), _empty_v3(phish_hit=True))
    assert s_cap.control_posture_applicable is False
    assert s_cap.control_posture_grade == "N/A"
    assert s_cap.threat_pressure_score == 25
    assert s_cap.threat_pressure_level == "Moderate"
    assert s_cap.action_posture == "Brand Protection Alert"

    # 3. WellsFargo-style: live MCP without RFC 9728, 0 official registry, 0 external pressure -> 0 (F) + None (0) -> Proactive Hardening
    t_wf = BrandTarget(domain="bankmcp.com", brand="bankmcp", cohort="fortune_traditional")
    v2_wf = _empty_v2(dnssec=False)
    v2_wf["flags"]["live_mcp_endpoint_count"] = 1
    v2_wf["flags"]["missing_rfc9728_count"] = 1
    s_wf = score_audit(t_wf, [], _empty_v1(), v2_wf, _empty_v3())
    assert s_wf.control_posture_applicable is True
    assert s_wf.control_posture_score == 0
    assert s_wf.control_posture_grade == "F"
    assert s_wf.threat_pressure_score == 0
    assert s_wf.action_posture == "Proactive Hardening"

    # 4. Stripe-style: strong controls (no DNSSEC -> 88 B) + critical external pressure (95 Critical) -> Active Defense
    #    AND context-aware recommendations NEVER tell Stripe to claim registry or publish packages it already owns!
    t_str = BrandTarget(domain="paydemo.com", brand="paydemo", cohort="saas_ai_fintech")
    v1_str = {
        "mcp_registry": {
            "official_count": 1,
            "unverified_3p_hosted_proxy_count": 5,
            "url_path_token_exposed_count": 1,
            "unverified_3p_package_entry_count": 0,
            "entries": [{"name": "com.paydemo/mcp", "classification": "official_domain_anchored"}],
        },
        "npm": {
            "official_count": 1,
            "unverified_count": 15,
            "free_email_unverified_count": 10,
            "packages": [{"name": "@paydemo/mcp", "official_anchored": True, "is_scoped": True}],
        },
        "pypi": {"official_count": 1, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"official_registry_vacuum": False, "has_any_mcp_footprint": True},
    }
    v2_str = _empty_v2(dnssec=False, dns_aid=False)
    v2_str["flags"]["live_mcp_endpoint_count"] = 1
    v2_str["flags"]["rfc9728_present_count"] = 1
    f_tok = Finding(
        rule_id="v1_url_path_token_exposure",
        vector="V1",
        label="URL-Path Token Exposure",
        severity="critical",
        title="1 proxy embeds token",
        summary="Summary",
        owasp=owasp_list_for("v1_url_path_token_exposure"),
        evidence=[],
        recommendation="Claim your official reverse-DNS namespace",
    )
    f_proxy = Finding(
        rule_id="v1_unverified_3p_hosted_proxy",
        vector="V1",
        label="Unverified 3rd-Party Hosted Proxy",
        severity="high",
        title="5 proxies",
        summary="Summary",
        owasp=owasp_list_for("v1_unverified_3p_hosted_proxy"),
        evidence=[],
        recommendation="Claim your official reverse-DNS namespace",
    )
    f_free = Finding(
        rule_id="v1_unscoped_free_email_collision",
        vector="V1",
        label="Unverified Package / Free-Email Maintainer",
        severity="high",
        title="10 free email",
        summary="Summary",
        owasp=owasp_list_for("v1_unscoped_free_email_collision"),
        evidence=[],
        recommendation="Publish official scoped MCP packages",
    )
    s_str = score_audit(t_str, [f_tok, f_proxy, f_free], v1_str, v2_str, _empty_v3())
    assert s_str.control_posture_score == 88
    assert s_str.control_posture_grade == "B"
    assert s_str.threat_pressure_score == 95
    assert s_str.threat_pressure_level == "Critical"
    assert s_str.action_posture == "Active Defense"
    # Verify context-aware recommendations never tell paydemo to claim a registry or publish packages it already owns
    for rec in [f_tok.recommendation, f_proxy.recommendation, *s_str.external_defense_priorities]:
        assert "claim your official reverse-dns" not in rec.lower()
        assert "publish official scoped mcp packages" not in rec.lower()
    assert "trusted publishers" in f_free.recommendation.lower()

    # 5. Cloudflare-style: all production controls + apex DNSSEC (AD=true) -> 96 (Grade A)
    v2_cf = _empty_v2(dnssec=True, dns_aid=False)
    v2_cf["flags"]["live_mcp_endpoint_count"] = 7
    v2_cf["flags"]["rfc9728_present_count"] = 7
    s_cf = score_audit(t_str, [], v1_str, v2_cf, _empty_v3())
    assert s_cf.control_posture_score == 96
    assert s_cf.control_posture_grade == "A"
    assert s_cf.control_posture_label == "Exemplary"

    # 6. Slack-style: weak controls (F) + High external pressure -> Urgent Remediation
    v1_sl = {
        "mcp_registry": {"official_count": 0, "unverified_3p_hosted_proxy_count": 6, "url_path_token_exposed_count": 0, "entries": []},
        "npm": {"official_count": 0, "unverified_count": 16, "free_email_unverified_count": 9, "packages": []},
        "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"official_registry_vacuum": True, "has_any_mcp_footprint": True},
    }
    v2_sl = _empty_v2(dnssec=True, dns_aid=False)
    v2_sl["flags"]["live_mcp_endpoint_count"] = 1
    v2_sl["flags"]["missing_rfc9728_count"] = 1
    v2_sl["flags"]["cross_domain_drift_detected"] = True
    s_sl = score_audit(BrandTarget(domain="chatdemo.com", brand="chatdemo"), [], v1_sl, v2_sl, _empty_v3())
    assert s_sl.control_posture_score == 13
    assert s_sl.control_posture_grade == "F"
    assert s_sl.threat_pressure_score == 56
    assert s_sl.threat_pressure_level == "High"
    assert s_sl.action_posture == "Urgent Remediation"


def test_single_file_html_report_two_axis_escaping_inline_code_and_zero_external_deps() -> None:
    target = BrandTarget(domain="example.com", brand="example", sector="SaaS", cohort="saas_ai_fintech")
    finding_crit = Finding(
        rule_id="v1_url_path_token_exposure",
        vector="V1",
        label="URL-Path Token Exposure",
        severity="critical",
        title="1 proxy claiming <script>alert(1)</script> via `mcp.example.com`",
        summary="Uses `npx` / `uvx` without official anchor.",
        owasp=owasp_list_for("v1_url_path_token_exposure"),
        evidence=[
            Evidence(
                source="mcp_registry",
                locator="https://proxy.example.net/mcp/{token}",
                detail="Entry `net.example/proxy` exposes `{token}`",
                raw={"server": "net.example/proxy"},
            )
        ],
        recommendation="Enforce allowlists.",
    )
    finding_high = Finding(
        rule_id="v1_official_registry_vacuum",
        vector="V1",
        label="Official Registry Vacuum",
        severity="high",
        title="Zero official entries for `example.com`",
        summary="No official anchor.",
        owasp=owasp_list_for("v1_official_registry_vacuum"),
        evidence=[Evidence(source="mcp_registry", locator="https://registry.modelcontextprotocol.io", detail="0 official", raw={})],
        recommendation="Claim namespace.",
    )
    v1 = {
        "mcp_registry": {
            "official_count": 0,
            "unverified_3p_hosted_proxy_count": 1,
            "url_path_token_exposed_count": 1,
            "entries": [
                {"name": "net.example/proxy", "classification": "unverified_3p_hosted_proxy", "url_path_token_exposed": True, "remotes": [{"url": "https://proxy.example.net/{token}"}]},
                {"name": "com.example/mcp", "classification": "official_domain_anchored", "url_path_token_exposed": False, "remotes": [{"url": "https://mcp.example.com/mcp"}]},
            ],
        },
        "npm": {
            "official_count": 0,
            "unverified_count": 1,
            "free_email_unverified_count": 1,
            "packages": [
                {
                    "name": "@demo/mcp-example",
                    "official_anchored": False,
                    "free_email_maintainer": True,
                    "publisher_email_domain": "corp.example.org",
                    "free_email_domains": ["gmail.com"],
                    "downloads_monthly": 420,
                }
            ],
        },
        "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"official_registry_vacuum": True, "has_any_mcp_footprint": True},
    }
    v2 = _empty_v2(dnssec=False, dns_aid=False)
    v3 = _empty_v3()
    score = score_audit(target, [finding_crit, finding_high], v1, v2, v3)
    report = AuditReport(
        schema_version="2.0",
        tool_version="0.1.0",
        scanned_at="2026-11-21T12:00:00Z",
        duration_seconds=3.4,
        target=target,
        verified_sibling_domains=["example.com"],
        score=score,
        findings=[finding_crit, finding_high],
        vector1=v1,
        vector2=v2,
        vector3=v3,
    )

    html_out = render_html_report(report)
    assert "<!DOCTYPE html>" in html_out
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
    assert "<code>mcp.example.com</code>" in html_out
    assert "`mcp.example.com`" not in html_out
    assert "Axis 1 · First-Party Control Posture" in html_out
    assert "Axis 2 · External Threat Pressure" in html_out
    assert "First-Party Control Gaps (1)" in html_out
    assert "External Ecosystem Threats (1)" in html_out
    assert "corp.example.org (co-maintainer: gmail.com)" in html_out
    # Official entry sorted ahead of unverified proxy in MCP Registry table
    reg_section = html_out[html_out.index("Official MCP Registry Provenance Map"):]
    assert reg_section.index("com.example/mcp") < reg_section.index("net.example/proxy")
    # Critical drawer open by default; non-critical drawer collapsed
    assert html_out.count('<details class="ev-drawer" open>') == 1
    assert html_out.count('<details class="ev-drawer">') == 1
    assert "ASI04" in html_out
    assert "MCP09:2025" in html_out
    # Zero external stylesheet/script CDN calls
    assert not re.search(r"<(script|link)[^>]+https?://", html_out, re.IGNORECASE)


def test_anonymizer_strips_domains_and_renders_two_axis_cohort_markdown() -> None:
    batch = {
        "tool_version": "0.1.0",
        "started_at": "2026-11-21T12:00:00Z",
        "finished_at": "2026-11-21T12:05:00Z",
        "duration_seconds": 300.0,
        "reports": [
            {
                "target": {"domain": "secretbank.com", "brand": "secretbank", "sector": "Banking", "cohort": "fortune_traditional"},
                "score": {
                    "scoring_model": "2-axis-v1",
                    "control_posture_applicable": True,
                    "control_posture_score": 13,
                    "control_posture_grade": "F",
                    "threat_pressure_score": 40,
                    "threat_pressure_level": "Moderate",
                    "action_posture": "Action Required",
                    "counts_by_severity": {"high": 2},
                    "counts_by_axis": {"first_party_control": 1, "external_threat": 1},
                },
                "findings": [
                    {"rule_id": "v1_official_registry_vacuum", "owasp": [{"code": "ASI04"}, {"code": "MCP04:2025"}]}
                ],
                "vector1": {
                    "mcp_registry": {"official_count": 0, "unverified_3p_hosted_proxy_count": 1, "url_path_token_exposed_count": 0},
                    "npm": {"official_count": 0, "unverified_count": 1, "free_email_unverified_count": 1},
                    "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0},
                    "flags": {"official_registry_vacuum": True, "has_any_mcp_footprint": True},
                },
                "vector2": {
                    "flags": {"live_mcp_endpoint_count": 0, "rfc9728_present_count": 0, "missing_rfc9728_count": 0, "apex_dnssec_enabled": True, "dns_aid_present": False}
                },
                "vector3": {"flags": {"has_active_lookalike_agent_endpoint": False, "has_active_phishing_lookalike": False}},
            }
        ],
    }
    study = anonymize_batch_results(batch)
    serialized = str(study)
    assert "secretbank" not in serialized
    assert study["scoring_model"] == "2-axis-v1"
    assert study["anonymized_records"][0]["anon_id"] == "ENT-001"
    assert study["overall"]["graded_posture_count"] == 1
    assert study["overall"]["mean_control_posture"] == 13.0
    assert study["overall"]["mean_threat_pressure"] == 40.0
    md = render_study_markdown(study)
    assert "State of External Agentic Exposure 2027" in md
    assert "2-Axis Action Posture Breakdown" in md
    assert "secretbank" not in md
    assert "ASI04" in md
