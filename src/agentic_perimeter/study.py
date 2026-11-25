"""Anonymizer and statistical study aggregator for 'State of External Agentic Exposure 2027'.

Supports the 2-Axis Scoring Model (`2-axis-v1`):
  - Axis 1: First-Party Control Posture (strictly computed over graded brands vs. N/A Baseline)
  - Axis 2: External Ecosystem Threat Pressure (computed across all N brands, NO A-F grade)
  - 2D Executive Action Posture Distribution
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional


def _pct(num: int, den: int) -> float:
    return round((num / den) * 100.0, 1) if den > 0 else 0.0


def _median(vals: List[int]) -> Optional[float | int]:
    if not vals:
        return None
    s = sorted(vals)
    n = len(s)
    return s[n // 2] if n % 2 == 1 else round((s[n // 2 - 1] + s[n // 2]) / 2.0, 1)


def _mean(vals: List[int]) -> Optional[float]:
    if not vals:
        return None
    return round(sum(vals) / len(vals), 1)


def anonymize_batch_results(batch_data: Dict[str, Any]) -> Dict[str, Any]:
    """Strip brand/domain identifiers and sensitive live URLs from batch scan results,
    producing a responsible-disclosure-safe empirical dataset and aggregated cohort metrics.
    """
    reports: List[Dict[str, Any]] = batch_data.get("reports") or []
    cohort_counters: Dict[str, int] = {}
    anon_records: List[Dict[str, Any]] = []

    for rep in reports:
        target = rep.get("target") or {}
        cohort = str(target.get("cohort") or "custom")
        prefix = "ENT" if cohort == "fortune_traditional" else ("TECH" if cohort == "saas_ai_fintech" else "ORG")
        cohort_counters[prefix] = cohort_counters.get(prefix, 0) + 1
        anon_id = f"{prefix}-{cohort_counters[prefix]:03d}"

        v1 = rep.get("vector1") or {}
        v1_flags = v1.get("flags") or {}
        v1_reg = v1.get("mcp_registry") or {}
        v1_npm = v1.get("npm") or {}
        v1_pypi = v1.get("pypi") or {}
        v2 = rep.get("vector2") or {}
        v2_flags = v2.get("flags") or {}
        v3 = rep.get("vector3") or {}
        v3_flags = v3.get("flags") or {}
        score = rep.get("score") or {}
        findings = rep.get("findings") or []

        owasp_codes = sorted(
            {o.get("code") for f in findings for o in (f.get("owasp") or []) if o.get("code")}
        )
        rule_ids = sorted({f.get("rule_id") for f in findings if f.get("rule_id")})

        posture_applicable = bool(score.get("control_posture_applicable", False))
        posture_score = score.get("control_posture_score") if posture_applicable else None
        posture_grade = str(score.get("control_posture_grade") or "N/A")
        threat_score = int(score.get("threat_pressure_score") or 0)
        threat_level = str(score.get("threat_pressure_level") or "None")
        action_posture = str(score.get("action_posture") or "Baseline — Monitor")

        anon_records.append(
            {
                "anon_id": anon_id,
                "cohort": cohort,
                "sector": target.get("sector", "Unknown"),
                "scoring_model": score.get("scoring_model", "2-axis-v1"),
                "control_posture_applicable": posture_applicable,
                "control_posture_score": posture_score,
                "control_posture_grade": posture_grade,
                "threat_pressure_score": threat_score,
                "threat_pressure_level": threat_level,
                "action_posture": action_posture,
                "counts_by_severity": score.get("counts_by_severity") or {},
                "counts_by_axis": score.get("counts_by_axis") or {},
                "rule_ids": rule_ids,
                "owasp_codes": owasp_codes,
                "metrics": {
                    "official_mcp_registry_count": v1_reg.get("official_count", 0),
                    "unverified_3p_hosted_proxy_count": v1_reg.get("unverified_3p_hosted_proxy_count", 0),
                    "url_path_token_exposed_count": v1_reg.get("url_path_token_exposed_count", 0),
                    "official_registry_vacuum": bool(v1_flags.get("official_registry_vacuum")),
                    "has_any_mcp_footprint": bool(v1_flags.get("has_any_mcp_footprint")),
                    "npm_official_count": v1_npm.get("official_count", 0),
                    "npm_unverified_count": v1_npm.get("unverified_count", 0),
                    "npm_free_email_unverified_count": v1_npm.get("free_email_unverified_count", 0),
                    "pypi_official_count": v1_pypi.get("official_count", 0),
                    "pypi_unverified_count": v1_pypi.get("unverified_count", 0),
                    "pypi_free_email_unverified_count": v1_pypi.get("free_email_unverified_count", 0),
                    "live_mcp_endpoint_count": v2_flags.get("live_mcp_endpoint_count", 0),
                    "rfc9728_present_count": v2_flags.get("rfc9728_present_count", 0),
                    "missing_rfc9728_count": v2_flags.get("missing_rfc9728_count", 0),
                    "broad_oauth_scope_detected": bool(v2_flags.get("broad_oauth_scope_detected")),
                    "cross_domain_drift_detected": bool(v2_flags.get("cross_domain_drift_detected")),
                    "cross_domain_3p_delegation_detected": bool(v2_flags.get("cross_domain_3p_delegation_detected")),
                    "apex_dnssec_enabled": bool(v2_flags.get("apex_dnssec_enabled")),
                    "dns_aid_present": bool(v2_flags.get("dns_aid_present")),
                    "active_lookalike_agent_endpoint": bool(v3_flags.get("has_active_lookalike_agent_endpoint")),
                    "active_phishing_lookalike": bool(v3_flags.get("has_active_phishing_lookalike")),
                },
            }
        )

    def _summarize_slice(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        n = len(rows)
        if n == 0:
            return {"count": 0}

        def count_where(fn) -> int:
            return sum(1 for r in rows if fn(r))

        graded_scores = [
            int(r["control_posture_score"])
            for r in rows
            if r.get("control_posture_score") is not None
        ]
        graded_n = len(graded_scores)
        baseline_na_n = n - graded_n

        threat_scores = [int(r["threat_pressure_score"]) for r in rows]

        grade_dist = Counter(r["control_posture_grade"] for r in rows)
        threat_dist = Counter(r["threat_pressure_level"] for r in rows)
        action_dist = Counter(r["action_posture"] for r in rows)
        owasp_dist = Counter(c for r in rows for c in r["owasp_codes"])
        rule_dist = Counter(rid for r in rows for rid in r["rule_ids"])

        with_live_mcp = count_where(lambda r: r["metrics"]["live_mcp_endpoint_count"] > 0)
        with_missing_rfc = count_where(lambda r: r["metrics"]["missing_rfc9728_count"] > 0)
        with_any_mcp = count_where(lambda r: r["metrics"]["has_any_mcp_footprint"])
        with_vacuum = count_where(lambda r: r["metrics"]["official_registry_vacuum"])
        with_official = count_where(lambda r: r["metrics"]["official_mcp_registry_count"] > 0)
        with_3p_proxy = count_where(lambda r: r["metrics"]["unverified_3p_hosted_proxy_count"] > 0)
        with_token_url = count_where(lambda r: r["metrics"]["url_path_token_exposed_count"] > 0)
        with_free_email = count_where(
            lambda r: (r["metrics"]["npm_free_email_unverified_count"] + r["metrics"]["pypi_free_email_unverified_count"]) > 0
        )
        with_unverified_pkg = count_where(
            lambda r: (r["metrics"]["npm_unverified_count"] + r["metrics"]["pypi_unverified_count"]) > 0
        )
        with_broad_oauth = count_where(lambda r: r["metrics"]["broad_oauth_scope_detected"])
        with_cross_drift = count_where(lambda r: r["metrics"]["cross_domain_drift_detected"])
        with_dnssec = count_where(lambda r: r["metrics"]["apex_dnssec_enabled"])
        with_dns_aid = count_where(lambda r: r["metrics"]["dns_aid_present"])
        with_v3_mcp = count_where(lambda r: r["metrics"]["active_lookalike_agent_endpoint"])
        with_v3_phish = count_where(lambda r: r["metrics"]["active_phishing_lookalike"])

        return {
            "count": n,
            "graded_posture_count": graded_n,
            "baseline_na_count": baseline_na_n,
            "mean_control_posture": _mean(graded_scores),
            "median_control_posture": _median(graded_scores),
            "control_posture_grade_distribution": {
                g: grade_dist.get(g, 0) for g in ("A", "B", "C", "D", "F", "N/A")
            },
            "mean_threat_pressure": _mean(threat_scores) or 0.0,
            "median_threat_pressure": _median(threat_scores) or 0.0,
            "threat_pressure_level_distribution": {
                lvl: threat_dist.get(lvl, 0) for lvl in ("Critical", "High", "Moderate", "Low", "None")
            },
            "action_posture_distribution": dict(sorted(action_dist.items(), key=lambda kv: (-kv[1], kv[0]))),
            "prevalence": {
                "has_any_mcp_footprint": {"count": with_any_mcp, "pct": _pct(with_any_mcp, n)},
                "official_mcp_registry_present": {"count": with_official, "pct": _pct(with_official, n)},
                "official_registry_vacuum": {"count": with_vacuum, "pct": _pct(with_vacuum, n)},
                "official_registry_vacuum_among_mcp_footprint": {
                    "count": with_vacuum,
                    "denominator": with_any_mcp,
                    "pct": _pct(with_vacuum, with_any_mcp),
                },
                "unverified_3p_hosted_proxy": {"count": with_3p_proxy, "pct": _pct(with_3p_proxy, n)},
                "url_path_token_exposure": {"count": with_token_url, "pct": _pct(with_token_url, n)},
                "unverified_npm_or_pypi_package": {"count": with_unverified_pkg, "pct": _pct(with_unverified_pkg, n)},
                "free_email_maintainer_collision": {"count": with_free_email, "pct": _pct(with_free_email, n)},
                "live_first_party_mcp_endpoint": {"count": with_live_mcp, "pct": _pct(with_live_mcp, n)},
                "missing_rfc9728_among_live_mcp": {
                    "count": with_missing_rfc,
                    "denominator": with_live_mcp,
                    "pct": _pct(with_missing_rfc, with_live_mcp),
                },
                "broad_oauth_scope_declaration": {"count": with_broad_oauth, "pct": _pct(with_broad_oauth, n)},
                "cross_domain_perimeter_drift": {"count": with_cross_drift, "pct": _pct(with_cross_drift, n)},
                "apex_dnssec_enabled": {"count": with_dnssec, "pct": _pct(with_dnssec, n)},
                "dns_aid_present": {"count": with_dns_aid, "pct": _pct(with_dns_aid, n)},
                "active_lookalike_agent_endpoint": {"count": with_v3_mcp, "pct": _pct(with_v3_mcp, n)},
                "active_phishing_lookalike": {"count": with_v3_phish, "pct": _pct(with_v3_phish, n)},
            },
            "owasp_prevalence": {
                k: {"count": v, "pct": _pct(v, n)} for k, v in sorted(owasp_dist.items())
            },
            "rule_prevalence": {
                k: {"count": v, "pct": _pct(v, n)} for k, v in sorted(rule_dist.items())
            },
        }

    cohorts_present = sorted({r["cohort"] for r in anon_records})
    by_cohort = {
        c: _summarize_slice([r for r in anon_records if r["cohort"] == c]) for c in cohorts_present
    }
    sectors_present = sorted({r["sector"] for r in anon_records})
    by_sector = {
        s: _summarize_slice([r for r in anon_records if r["sector"] == s]) for s in sectors_present
    }

    return {
        "study_title": "State of External Agentic Exposure 2027",
        "schema_version": "2.0",
        "scoring_model": "2-axis-v1",
        "tool_version": batch_data.get("tool_version"),
        "scanned_window": {
            "started_at": batch_data.get("started_at"),
            "finished_at": batch_data.get("finished_at"),
            "duration_seconds": batch_data.get("duration_seconds"),
        },
        "responsible_disclosure_note": (
            "All target domains, brand names, and live misconfiguration URLs have been stripped and "
            "replaced with anonymized cohort identifiers (ENT-xxx, TECH-xxx) in accordance with "
            "responsible disclosure policy."
        ),
        "overall": _summarize_slice(anon_records),
        "by_cohort": by_cohort,
        "by_sector": by_sector,
        "anonymized_records": anon_records,
    }


def render_study_markdown(study: Dict[str, Any]) -> str:
    """Render a crisp, publication-grade English Markdown summary of the anonymized Top-100 study."""
    overall = study.get("overall") or {}
    n = overall.get("count", 0)
    prev = overall.get("prevalence") or {}
    by_cohort = study.get("by_cohort") or {}
    ent = by_cohort.get("fortune_traditional") or {}
    tech = by_cohort.get("saas_ai_fintech") or {}
    ent_p = ent.get("prevalence") or {}
    tech_p = tech.get("prevalence") or {}

    def fmt_cell(pdict: Dict[str, Any], key: str) -> str:
        item = pdict.get(key)
        if not item:
            return "—"
        if "denominator" in item:
            return f"{item['count']}/{item['denominator']} ({item['pct']}%)"
        return f"{item['count']} ({item['pct']}%)"

    def fmt_opt(val: Any) -> str:
        return "N/A" if val is None else str(val)

    metrics_rows = [
        ("Any external MCP ecosystem footprint", "has_any_mcp_footprint"),
        ("Official domain-anchored MCP Registry entry", "official_mcp_registry_present"),
        ("**Official Registry Vacuum** (0 official + >=1 unverified 3P)", "official_registry_vacuum"),
        ("**Unverified 3rd-Party Hosted MCP Proxy** claiming brand", "unverified_3p_hosted_proxy"),
        ("**URL-Path Token Exposure** in 3P proxy template", "url_path_token_exposure"),
        ("Unverified npm or PyPI MCP package claiming brand", "unverified_npm_or_pypi_package"),
        ("**Free-Email Maintainer** on unverified MCP package", "free_email_maintainer_collision"),
        ("Live first-party `mcp.*` / `agents.*` endpoint", "live_first_party_mcp_endpoint"),
        ("Missing RFC 9728 metadata (among live MCP endpoints)", "missing_rfc9728_among_live_mcp"),
        ("Broad OAuth Scope Declaration", "broad_oauth_scope_declaration"),
        ("Cross-Domain Perimeter Drift", "cross_domain_perimeter_drift"),
        ("Apex DNSSEC validated (`AD=true`)", "apex_dnssec_enabled"),
        ("IETF DNS-AID (`_agent` / `_mcp` SVCB/TXT) present", "dns_aid_present"),
        ("Active Lookalike Agent Endpoint (V3 high-signal)", "active_lookalike_agent_endpoint"),
        ("Phishing-Warning Lookalike Domain (V3 high-signal)", "active_phishing_lookalike"),
    ]

    table_lines = [
        "| Metric | All Brands (N="
        + str(n)
        + ") | Traditional Fortune/S&P 500 (N="
        + str(ent.get("count", 0))
        + ") | SaaS / Fintech / Cloud / AI (N="
        + str(tech.get("count", 0))
        + ") |",
        "|---|---:|---:|---:|",
    ]
    for label, key in metrics_rows:
        table_lines.append(
            f"| {label} | {fmt_cell(prev, key)} | {fmt_cell(ent_p, key)} | {fmt_cell(tech_p, key)} |"
        )

    # 2-Axis Action Posture table
    action_order = [
        "Urgent Remediation",
        "Action Required",
        "Priority Hardening",
        "Proactive Hardening",
        "Hardening & Monitoring",
        "Targeted Hardening",
        "Active Defense",
        "Active Monitoring",
        "Well-Positioned",
        "Brand Protection Alert",
        "Baseline — Monitor",
    ]
    all_act = overall.get("action_posture_distribution") or {}
    ent_act = ent.get("action_posture_distribution") or {}
    tech_act = tech.get("action_posture_distribution") or {}
    action_lines = [
        f"| 2-Axis Action Posture | All Brands (N={n}) | Traditional Fortune/S&P 500 (N={ent.get('count', 0)}) | SaaS / Fintech / Cloud / AI (N={tech.get('count', 0)}) |",
        "|---|---:|---:|---:|",
    ]
    for ap in action_order:
        c_all = all_act.get(ap, 0)
        if c_all == 0:
            continue
        c_ent = ent_act.get(ap, 0)
        c_tech = tech_act.get(ap, 0)
        action_lines.append(
            f"| **{ap}** | {c_all} ({_pct(c_all, n)}%) | {c_ent} ({_pct(c_ent, ent.get('count', 0))}%) | {c_tech} ({_pct(c_tech, tech.get('count', 0))}%) |"
        )

    owasp_lines = [
        "| OWASP Mapping | Affected Brands (N=" + str(n) + ") | Prevalence |",
        "|---|---:|---:|",
    ]
    for code, stat in sorted((overall.get("owasp_prevalence") or {}).items()):
        owasp_lines.append(f"| `{code}` | {stat['count']} | {stat['pct']}% |")

    sector_lines = [
        "| Sector | Graded / Total | Mean Posture (Graded) | Mean Threat Pressure | Official Registry | Registry Vacuum | 3P Hosted Proxy | Free-Email Pkg | DNSSEC |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for sec, sdata in sorted((study.get("by_sector") or {}).items()):
        sp = sdata.get("prevalence") or {}
        graded_str = f"{sdata.get('graded_posture_count', 0)}/{sdata.get('count', 0)}"
        posture_str = fmt_opt(sdata.get("mean_control_posture"))
        threat_str = str(sdata.get("mean_threat_pressure", 0.0))
        sector_lines.append(
            f"| {sec} | {graded_str} | {posture_str} | {threat_str} | "
            f"{(sp.get('official_mcp_registry_present') or {}).get('pct', 0)}% | "
            f"{(sp.get('official_registry_vacuum') or {}).get('pct', 0)}% | "
            f"{(sp.get('unverified_3p_hosted_proxy') or {}).get('pct', 0)}% | "
            f"{(sp.get('free_email_maintainer_collision') or {}).get('pct', 0)}% | "
            f"{(sp.get('apex_dnssec_enabled') or {}).get('pct', 0)}% |"
        )

    grades = overall.get("control_posture_grade_distribution") or {}
    threats = overall.get("threat_pressure_level_distribution") or {}
    win = study.get("scanned_window") or {}

    return "\n".join(
        [
            f"# {study.get('study_title')} — Anonymized Empirical Summary",
            "",
            f"**Dataset Size:** {n} public brands ({ent.get('count', 0)} Traditional Fortune/S&P 500 + {tech.get('count', 0)} SaaS/Fintech/Cloud/AI)  ",
            f"**Scan Window:** `{win.get('started_at')}` to `{win.get('finished_at')}` (`{win.get('duration_seconds')}s`)  ",
            f"**Tool & Scoring Model:** `agentic-perimeter` v{study.get('tool_version')} · `{study.get('scoring_model', '2-axis-v1')}` (100% passive, read-only public APIs, DoH, CT/TLS SAN)  ",
            f"**Axis 1 — First-Party Control Posture (Graded N={overall.get('graded_posture_count', 0)}; Baseline N/A={overall.get('baseline_na_count', 0)}):** Mean `{fmt_opt(overall.get('mean_control_posture'))}` / Median `{fmt_opt(overall.get('median_control_posture'))}` (Grades: A={grades.get('A', 0)}, B={grades.get('B', 0)}, C={grades.get('C', 0)}, D={grades.get('D', 0)}, F={grades.get('F', 0)}, N/A={grades.get('N/A', 0)})  ",
            f"**Axis 2 — External Ecosystem Threat Pressure (All N={n}):** Mean `{overall.get('mean_threat_pressure', 0.0)}` / Median `{overall.get('median_threat_pressure', 0.0)}` (Levels: Critical={threats.get('Critical', 0)}, High={threats.get('High', 0)}, Moderate={threats.get('Moderate', 0)}, Low={threats.get('Low', 0)}, None={threats.get('None', 0)})",
            "",
            "> **Responsible Disclosure & Neutrality Notice:** " + str(study.get("responsible_disclosure_note")),
            "",
            "---",
            "",
            "## 1. Cohort Comparison: Traditional Enterprise vs. SaaS / Fintech / AI",
            "",
            *table_lines,
            "",
            "## 2. 2-Axis Action Posture Breakdown",
            "",
            *action_lines,
            "",
            "## 3. OWASP Agentic Top 10 (2026) & OWASP MCP Top 10 (2025) Prevalence",
            "",
            *owasp_lines,
            "",
            "## 4. Breakdown by Industry Sector",
            "",
            *sector_lines,
            "",
            "## 5. Methodology Summary (Passive-Only, 2-Axis Scoring Model)",
            "",
            "- **2-Axis Scoring (`2-axis-v1`):** Separates **Axis 1 — First-Party Control Posture** (0–100, higher = better, Grade `A–F` across applicable controls `C1–C6`: Official Registry, Official Scoped Packages, RFC 9728 coverage, Least-Privilege OAuth Scopes, Domain Boundary Consistency, and DNSSEC/DNS-AID; brands with zero external agentic footprint receive `N/A Baseline` instead of an inflated Grade A) from **Axis 2 — External Ecosystem Threat Pressure** (0–100, higher = heavier third-party pressure across `T1–T6`: URL-Path Token Exposure, Unverified 3P Proxies, Free-Email Maintainer Collisions, Unverified Packages, Active Lookalike Agent Endpoints, and Phishing-Warning Lookalikes; levels `None`–`Critical` with no A–F grade).",
            "- **V1 (MCP Supply-Chain Provenance):** Queries `registry.modelcontextprotocol.io/v0.1/servers`, npm Registry API, PyPI JSON API, and GitHub REST API. Anchors official assets using reverse-DNS prefixes, verified sibling domains, GitHub org `blog`/`email` verification, and cross-registry npm/PyPI maintainer email anchoring. Applies homonym and generic-wrapper filters to suppress false attributions.",
            "- **V2 (External Perimeter, DNS-AID & OAuth):** Queries Google/Cloudflare DoH (`do=1` for DNSSEC `AD` bit) for `_agent.<domain>` and `_mcp.<domain>` SVCB/TXT/SRV records, Certificate Transparency (CertSpotter primary + `crt.sh` fallback) + live TLS SAN inspection for `mcp.*` / `agents.*`, and passive HTTP GET on RFC 9728 (`/.well-known/oauth-protected-resource`) and standard `.well-known` discovery documents.",
            "- **V3 (Silent Active Lookalike Sub-Check):** Silently suppresses domain parking, GoDaddy/Afternic landers, Cloudflare HTTP 523 squatters, and defensive brand registrations; flags only confirmed active `/mcp` / `.well-known` agent endpoints or third-party phishing warning interstitials.",
            "",
        ]
    )
