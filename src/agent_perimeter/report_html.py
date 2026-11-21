"""Single-file, self-contained executive HTML report generator readable by a CISO in 30 seconds.

Implements the 2-Axis Scoring Model (`2-axis-v1`):
  - Axis 1: First-Party Control Posture (0-100, higher = better, Grade A-F or N/A Baseline)
  - Axis 2: External Ecosystem Threat Pressure (0-100, higher = heavier pressure, NO letter grade)
  - 2D Executive Action Posture Banner, 6-Control Checklist, Owner-Split Priorities, Axis-Grouped Findings.

Zero external network dependencies (no CDN CSS/JS/fonts); print-friendly; strict HTML escaping.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any, Dict, List, Optional

from .models import AuditReport

_SEV_COLORS: Dict[str, tuple[str, str, str]] = {
    # (bg, text, border)
    "critical": ("#fef2f2", "#991b1b", "#fecaca"),
    "high": ("#fff7ed", "#9a3412", "#fed7aa"),
    "medium": ("#fefce8", "#854d0e", "#fef08a"),
    "low": ("#eff6ff", "#1e40af", "#bfdbfe"),
    "info": ("#f1f5f9", "#334155", "#cbd5e1"),
}

_POSTURE_COLOR: Dict[str, str] = {
    "A": "#16a34a",
    "B": "#2563eb",
    "C": "#d97706",
    "D": "#ea580c",
    "F": "#dc2626",
    "N/A": "#64748b",
}

_THREAT_COLOR: Dict[str, tuple[str, str, str]] = {
    # (accent, pill_bg, pill_text)
    "Critical": ("#dc2626", "rgba(220, 38, 38, 0.22)", "#fecaca"),
    "High": ("#ea580c", "rgba(234, 88, 12, 0.22)", "#fed7aa"),
    "Moderate": ("#d97706", "rgba(217, 119, 6, 0.22)", "#fde68a"),
    "Low": ("#2563eb", "rgba(37, 99, 235, 0.22)", "#bfdbfe"),
    "None": ("#64748b", "rgba(100, 116, 139, 0.24)", "#cbd5e1"),
}

_ACTION_PILL_STYLE: Dict[str, tuple[str, str]] = {
    # (bg, text)
    "Well-Positioned": ("#16a34a", "#ffffff"),
    "Active Monitoring": ("#2563eb", "#ffffff"),
    "Active Defense": ("#0284c7", "#ffffff"),
    "Targeted Hardening": ("#d97706", "#ffffff"),
    "Hardening & Monitoring": ("#d97706", "#ffffff"),
    "Priority Hardening": ("#ea580c", "#ffffff"),
    "Proactive Hardening": ("#ea580c", "#ffffff"),
    "Action Required": ("#dc2626", "#ffffff"),
    "Urgent Remediation": ("#dc2626", "#ffffff"),
    "Baseline — Monitor": ("#475569", "#f8fafc"),
    "Brand Protection Alert": ("#b45309", "#ffffff"),
}

_INLINE_CODE_RE = re.compile(r"`([^`]+)`")


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _fmt_inline_code(value: Any) -> str:
    """Strictly HTML-escape first, then safely convert inline `code` spans to <code>...</code>."""
    escaped = _e(value)
    return _INLINE_CODE_RE.sub(r"<code>\1</code>", escaped)


def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def _posture_ring_svg(score: Optional[int], grade: str, applicable: bool) -> str:
    radius = 38
    circ = 2 * 3.14159265 * radius
    color = _POSTURE_COLOR.get(grade, "#64748b")
    if not applicable or score is None:
        return f"""
        <svg width="96" height="96" viewBox="0 0 96 96" aria-label="First-Party Control Posture: Not Applicable Baseline">
          <circle cx="48" cy="48" r="{radius}" fill="none" stroke="#334155" stroke-width="8" stroke-dasharray="6 5"/>
          <text x="48" y="46" text-anchor="middle" fill="#cbd5e1" font-size="22" font-weight="700" font-family="system-ui, -apple-system, sans-serif">N/A</text>
          <text x="48" y="63" text-anchor="middle" fill="#94a3b8" font-size="10" font-weight="600" font-family="system-ui, -apple-system, sans-serif">BASELINE</text>
        </svg>
        """
    pct = max(0, min(100, int(score)))
    dash = (pct / 100.0) * circ
    return f"""
    <svg width="96" height="96" viewBox="0 0 96 96" aria-label="First-Party Control Posture: Grade {_e(grade)}, {pct} out of 100">
      <circle cx="48" cy="48" r="{radius}" fill="none" stroke="#1e293b" stroke-width="8"/>
      <circle cx="48" cy="48" r="{radius}" fill="none" stroke="{color}" stroke-width="8"
              stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"
              transform="rotate(-90 48 48)"/>
      <text x="48" y="45" text-anchor="middle" fill="#f8fafc" font-size="24" font-weight="750" font-family="system-ui, -apple-system, sans-serif">{_e(grade)}</text>
      <text x="48" y="63" text-anchor="middle" fill="#94a3b8" font-size="11" font-weight="600" font-family="system-ui, -apple-system, sans-serif">{pct}/100</text>
    </svg>
    """


def _render_control_breakdown(control_breakdown: List[Dict[str, Any]], applicable: bool, v2_dns_aid: Dict[str, Any]) -> str:
    if not applicable:
        dnssec_ok = bool(v2_dns_aid.get("apex_dnssec_ad"))
        dns_aid_ok = bool(v2_dns_aid.get("dns_aid_present"))
        dnssec_pill = '<span class="pill ok-pill">AD=true</span>' if dnssec_ok else '<span class="pill neutral-pill">AD=false</span>'
        dns_aid_pill = '<span class="pill ok-pill">Present</span>' if dns_aid_ok else '<span class="pill neutral-pill">Not Detected</span>'
        return f"""
        <section class="panel baseline-panel" aria-label="Baseline Readiness Summary">
          <h2>First-Party Control Posture — Baseline Readiness <span class="pill neutral-pill">N/A · NO AGENTIC FOOTPRINT</span></h2>
          <p style="margin:0 0 12px 0; color:#334155;">
            No external MCP registry entries, brand-named MCP packages, or live first-party <code>mcp.*</code> endpoints were detected.
            First-Party Control Posture is marked <strong>N/A (Baseline)</strong> rather than an inflated Grade A.
            Proactive cryptographic DNS readiness is shown below ahead of future agentic adoption:
          </p>
          <div class="baseline-strip">
            <div class="baseline-chip"><span>Apex DNSSEC</span> {dnssec_pill}</div>
            <div class="baseline-chip"><span>IETF DNS-AID (<code>_agent</code>/<code>_mcp</code>)</span> {dns_aid_pill}</div>
            <div class="baseline-chip"><span>Official MCP Registry</span> <span class="pill neutral-pill">0 Entries</span></div>
            <div class="baseline-chip"><span>Live First-Party MCP</span> <span class="pill neutral-pill">0 Endpoints</span></div>
          </div>
        </section>
        """

    rows: List[str] = []
    for ctrl in control_breakdown:
        st = str(ctrl.get("status") or "na").lower()
        if st == "pass":
            st_pill = '<span class="pill ok-pill">PASS</span>'
        elif st == "partial":
            st_pill = '<span class="pill warn-pill">PARTIAL</span>'
        elif st == "gap":
            st_pill = '<span class="pill crit-pill">GAP</span>'
        else:
            st_pill = '<span class="pill neutral-pill">N/A</span>'

        earned = ctrl.get("earned")
        max_pts = ctrl.get("max_points", 0)
        pts_str = "—" if earned is None or st in ("na", "baseline") else f"{earned}/{max_pts}"
        rows.append(
            f"<tr>"
            f"<td><strong>{_e(ctrl.get('id'))}</strong> · {_e(ctrl.get('name'))}</td>"
            f"<td>{st_pill}</td>"
            f"<td class=\"num-cell\"><code>{_e(pts_str)}</code></td>"
            f"<td>{_fmt_inline_code(ctrl.get('detail'))}</td>"
            f"</tr>"
        )
    return f"""
    <section class="panel" aria-label="First-Party Control Posture Breakdown">
      <h2>First-Party Control Posture Breakdown <span class="muted" style="font-size:12px;">Normalized across applicable controls (higher = better)</span></h2>
      <table>
        <thead><tr><th>Control</th><th>Status</th><th class="num-cell">Points</th><th>Observed Posture</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </section>
    """


def _render_finding_card(finding: Dict[str, Any]) -> str:
    sev = str(finding.get("severity") or "info").lower()
    axis = str(finding.get("axis") or "external_threat").lower()
    bg, fg, border = _SEV_COLORS.get(sev, _SEV_COLORS["info"])
    axis_badge = (
        '<span class="axis-badge axis-fp">FIRST-PARTY CONTROL</span>'
        if axis == "first_party_control"
        else '<span class="axis-badge axis-ext">EXTERNAL THREAT</span>'
    )
    owasp_pills = "".join(
        f'<span class="pill owasp-pill" title="{_e(o.get("framework"))}: {_e(o.get("title"))}">{_e(o.get("code"))}</span>'
        for o in (finding.get("owasp") or [])
    )
    ev_rows: List[str] = []
    for ev in finding.get("evidence") or []:
        raw_pretty = json.dumps(ev.get("raw") or {}, indent=2, ensure_ascii=False)
        ev_rows.append(
            f"""
            <div class="ev-item">
              <div class="ev-head">
                <span class="ev-src">{_e(ev.get("source"))}</span>
                <code class="ev-loc">{_e(ev.get("locator"))}</code>
              </div>
              <div class="ev-detail">{_fmt_inline_code(ev.get("detail"))}</div>
              <details class="ev-raw">
                <summary>View raw verifiable evidence JSON</summary>
                <pre>{_e(raw_pretty)}</pre>
              </details>
            </div>
            """
        )
    ev_html = "".join(ev_rows) if ev_rows else '<div class="muted">No additional evidence items.</div>'
    # Default-collapse non-critical evidence drawers for 30-second scannability
    drawer_open = " open" if sev == "critical" else ""

    return f"""
    <article class="finding-card" style="border-left: 4px solid {fg};">
      <div class="finding-top">
        <div class="finding-badges">
          <span class="sev-badge" style="background:{bg};color:{fg};border:1px solid {border};">{_e(sev.upper())}</span>
          {axis_badge}
          <span class="vec-badge">{_e(finding.get("vector"))}</span>
          <span class="label-badge">{_e(finding.get("label"))}</span>
        </div>
        <div class="owasp-row">{owasp_pills}</div>
      </div>
      <h3 class="finding-title">{_fmt_inline_code(finding.get("title"))}</h3>
      <p class="finding-summary">{_fmt_inline_code(finding.get("summary"))}</p>
      <div class="finding-rec"><strong>Recommended Action:</strong> {_fmt_inline_code(finding.get("recommendation"))}</div>
      <details class="ev-drawer"{drawer_open}>
        <summary>Verifiable Evidence ({len(finding.get("evidence") or [])})</summary>
        <div class="ev-list">{ev_html}</div>
      </details>
    </article>
    """


def _format_pkg_email_cell(pkg: Dict[str, Any], primary_key: str) -> str:
    primary = str(pkg.get(primary_key) or "").strip()
    free_doms = [str(d) for d in (pkg.get("free_email_domains") or []) if d]
    if pkg.get("free_email_maintainer") and free_doms:
        extra = [d for d in free_doms if d != primary]
        if primary and extra:
            return f"{primary} (co-maintainer: {', '.join(extra[:2])})"
        if not primary:
            return f"co-maintainer: {', '.join(free_doms[:2])}"
    return primary or "—"


def render_html_report(report: AuditReport | Dict[str, Any]) -> str:
    """Render a single-file CISO-ready executive HTML report from an AuditReport or dict."""
    data = report.to_dict() if isinstance(report, AuditReport) else report
    target = data.get("target") or {}
    score = data.get("score") or {}
    findings = data.get("findings") or []
    v1 = data.get("vector1") or {}
    v2 = data.get("vector2") or {}
    v3 = data.get("vector3") or {}

    domain = target.get("domain", "")
    brand = target.get("brand", "")
    siblings = data.get("verified_sibling_domains") or [domain]

    posture_applicable = bool(score.get("control_posture_applicable", False))
    posture_score = score.get("control_posture_score")
    posture_grade = str(score.get("control_posture_grade") or "N/A")
    posture_label = str(score.get("control_posture_label") or "Baseline (No Agentic Footprint)")
    control_breakdown = score.get("control_breakdown") or []

    threat_score = int(score.get("threat_pressure_score") or 0)
    threat_level = str(score.get("threat_pressure_level") or "None")
    threat_accent, threat_pill_bg, threat_pill_fg = _THREAT_COLOR.get(
        threat_level, _THREAT_COLOR["None"]
    )

    action_posture = str(score.get("action_posture") or "Baseline — Monitor")
    action_summary = str(score.get("action_posture_summary") or "")
    action_bg, action_fg = _ACTION_PILL_STYLE.get(action_posture, ("#475569", "#f8fafc"))

    sev_counts = score.get("counts_by_severity") or {}
    axis_counts = score.get("counts_by_axis") or {}

    v1_reg = v1.get("mcp_registry") or {}
    v1_npm = v1.get("npm") or {}
    v1_pypi = v1.get("pypi") or {}
    v2_flags = v2.get("flags") or {}
    v2_dns_aid = v2.get("dns_aid") or {}

    posture_status_line = (
        f"{posture_label} · {posture_score}/100"
        if posture_applicable and posture_score is not None
        else "Baseline · No Agentic Footprint"
    )

    takeaways_html = "".join(
        f"<li>{_fmt_inline_code(t)}</li>" for t in (score.get("ciso_takeaways") or [])
    )
    fp_prios = score.get("first_party_priorities") or []
    ext_prios = score.get("external_defense_priorities") or []
    fp_prios_html = (
        "".join(f"<li>{_fmt_inline_code(p)}</li>" for p in fp_prios)
        if fp_prios
        else '<li class="muted">No urgent first-party gaps; maintain current controls.</li>'
    )
    ext_prios_html = (
        "".join(f"<li>{_fmt_inline_code(p)}</li>" for p in ext_prios)
        if ext_prios
        else '<li class="muted">No active external third-party threats observed.</li>'
    )

    # Axis-grouped findings sections
    fp_findings = [f for f in findings if str(f.get("axis") or "") == "first_party_control"]
    ext_findings = [f for f in findings if str(f.get("axis") or "") != "first_party_control"]

    findings_sections: List[str] = []
    if not findings:
        findings_sections.append(
            '<div class="empty-state">No external agentic exposure findings triggered across V1, V2, or V3 passive checks.</div>'
        )
    else:
        if fp_findings:
            cards = "".join(_render_finding_card(f) for f in fp_findings)
            findings_sections.append(
                f'<div class="findings-group"><h3 class="group-heading">First-Party Control Gaps ({len(fp_findings)})</h3>{cards}</div>'
            )
        if ext_findings:
            cards = "".join(_render_finding_card(f) for f in ext_findings)
            findings_sections.append(
                f'<div class="findings-group"><h3 class="group-heading">External Ecosystem Threats ({len(ext_findings)})</h3>{cards}</div>'
            )
    findings_html = "".join(findings_sections)

    # Supply-chain inventory table (MCP Registry entries — official-first sorting)
    def _reg_sort_key(e: Dict[str, Any]) -> tuple[int, int, str]:
        cls = e.get("classification", "")
        if cls == "official_domain_anchored":
            return (0, 0, str(e.get("name") or ""))
        if e.get("url_path_token_exposed"):
            return (1, 0, str(e.get("name") or ""))
        if cls == "unverified_3p_hosted_proxy":
            return (2, 0, str(e.get("name") or ""))
        return (3, 0, str(e.get("name") or ""))

    reg_entries = sorted(v1_reg.get("entries") or [], key=_reg_sort_key)
    reg_rows: List[str] = []
    for entry in reg_entries[:25]:
        cls = entry.get("classification", "")
        if cls == "official_domain_anchored":
            cls_badge = '<span class="pill ok-pill">Official Domain-Anchored</span>'
        elif cls == "unverified_3p_hosted_proxy":
            tok_flag = ' <span class="pill crit-pill">URL-Path Token</span>' if entry.get("url_path_token_exposed") else ""
            cls_badge = f'<span class="pill warn-pill">Unverified 3P Hosted Proxy</span>{tok_flag}'
        else:
            cls_badge = '<span class="pill neutral-pill">Unverified 3P Entry</span>'
        remotes_str = ", ".join(r.get("url", "") for r in (entry.get("remotes") or [])[:2]) or "Package-only (no remote URL)"
        reg_rows.append(
            f"<tr><td><code>{_e(entry.get('name'))}</code></td><td>{cls_badge}</td><td><code>{_e(remotes_str)}</code></td></tr>"
        )
    reg_table_body = "".join(reg_rows) or '<tr><td colspan="3" class="muted">No relevant Official MCP Registry entries found.</td></tr>'

    # npm / PyPI collision table (official-first sorting)
    npm_sorted = sorted(
        v1_npm.get("packages") or [],
        key=lambda p: (0 if p.get("official_anchored") else 1, -(p.get("downloads_monthly") or 0), str(p.get("name") or "")),
    )
    pypi_sorted = sorted(
        v1_pypi.get("packages") or [],
        key=lambda p: (0 if p.get("official_anchored") else 1, str(p.get("name") or "")),
    )

    pkg_rows: List[str] = []
    for p in npm_sorted[:12]:
        prov = '<span class="pill ok-pill">Official</span>' if p.get("official_anchored") else (
            '<span class="pill warn-pill">Unverified (Free Email)</span>'
            if p.get("free_email_maintainer")
            else '<span class="pill neutral-pill">Unverified</span>'
        )
        dl = f"{p['downloads_monthly']:,}/mo" if p.get("downloads_monthly") else "—"
        email_cell = _format_pkg_email_cell(p, "publisher_email_domain")
        pkg_rows.append(
            f"<tr><td>npm</td><td><code>{_e(p.get('name'))}</code></td><td>{prov}</td>"
            f"<td>{_e(dl)}</td><td>{_e(email_cell)}</td></tr>"
        )
    for p in pypi_sorted[:8]:
        prov = '<span class="pill ok-pill">Official</span>' if p.get("official_anchored") else (
            '<span class="pill warn-pill">Unverified (Free Email)</span>'
            if p.get("free_email_maintainer")
            else '<span class="pill neutral-pill">Unverified</span>'
        )
        email_cell = _format_pkg_email_cell(p, "author_email_domain")
        pkg_rows.append(
            f"<tr><td>PyPI</td><td><code>{_e(p.get('name'))}</code></td><td>{prov}</td>"
            f"<td>—</td><td>{_e(email_cell)}</td></tr>"
        )
    pkg_table_body = "".join(pkg_rows) or '<tr><td colspan="5" class="muted">No brand-named MCP npm or PyPI packages found.</td></tr>'

    # V2 live endpoints table
    sub_rows: List[str] = []
    for sub in v2.get("subdomains") or []:
        if not sub.get("effectively_live"):
            continue
        rfc = sub.get("rfc9728")
        if rfc:
            n_scopes = len(rfc.get("scopes_supported") or [])
            rfc_html = f'<span class="pill ok-pill">Present ({_plural(n_scopes, "scope")})</span>'
        elif sub.get("missing_rfc9728"):
            rfc_html = '<span class="pill warn-pill">Missing RFC 9728</span>'
        else:
            rfc_html = '<span class="pill neutral-pill">N/A</span>'
        root_st = (sub.get("http_root") or {}).get("status", 0)
        mcp_st = (sub.get("http_mcp") or {}).get("status", 0)
        sub_rows.append(
            f"<tr><td><code>{_e(sub.get('fqdn'))}</code></td>"
            f"<td>{'Yes' if sub.get('confirmed_mcp_endpoint') else 'No'}</td>"
            f"<td>HTTP {_e(root_st)} / HTTP {_e(mcp_st)}</td>"
            f"<td>{rfc_html}</td>"
            f"<td>{'AD=true' if sub.get('dnssec_ad') else 'AD=false'}</td></tr>"
        )
    sub_table_body = "".join(sub_rows) or '<tr><td colspan="5" class="muted">No live agent/MCP subdomains detected.</td></tr>'

    # V3 status summary
    v3_active_cnt = len(v3.get("active_agent_endpoints") or []) + len(v3.get("phishing_flagged") or [])
    v3_status = (
        f"{_plural(v3_active_cnt, 'active alert')}"
        if v3_active_cnt > 0
        else f"Clean ({v3.get('permutations_tested', 0)} permutations checked; parking/523 noise suppressed)"
    )

    unv_pkg_cnt = (v1_npm.get("unverified_count") or 0) + (v1_pypi.get("unverified_count") or 0)
    free_email_cnt = (v1_npm.get("free_email_unverified_count") or 0) + (v1_pypi.get("free_email_unverified_count") or 0)

    control_panel_html = _render_control_breakdown(control_breakdown, posture_applicable, v2_dns_aid)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>External Agentic Exposure Report — {_e(domain)} | agent-perimeter</title>
<style>
  :root {{
    --bg: #f8fafc;
    --card: #ffffff;
    --ink: #0f172a;
    --muted: #475569;
    --line: #e2e8f0;
    --navy: #0f172a;
    --navy-soft: #1e293b;
    --accent: #2563eb;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    font-size: 14px;
  }}
  .hero {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #f8fafc;
    padding: 24px 0 0 0;
    border-bottom: 1px solid #334155;
  }}
  .wrap {{ max-width: 1120px; margin: 0 auto; padding: 0 18px; }}
  .hero-grid {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    padding-bottom: 20px;
  }}
  .hero-id {{ flex: 1 1 320px; min-width: 260px; }}
  .eyebrow {{
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 11px;
    font-weight: 700;
    color: #93c5fd;
    margin-bottom: 6px;
  }}
  h1 {{ margin: 0 0 8px 0; font-size: 28px; font-weight: 750; letter-spacing: -0.02em; }}
  .meta-line {{ color: #cbd5e1; font-size: 12.5px; display: flex; flex-wrap: wrap; gap: 8px 16px; }}
  .scoreboard {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: stretch;
  }}
  .axis-card {{
    display: flex;
    align-items: center;
    gap: 14px;
    background: rgba(15, 23, 42, 0.62);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 12px 16px;
    min-width: 265px;
  }}
  .axis-card-threat {{
    flex-direction: column;
    align-items: flex-start;
    justify-content: center;
    gap: 6px;
    min-width: 250px;
  }}
  .axis-kicker {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #94a3b8;
  }}
  .axis-status {{
    font-size: 16px;
    font-weight: 700;
    color: #f8fafc;
    margin: 2px 0;
  }}
  .axis-caption {{
    font-size: 11.5px;
    color: #94a3b8;
  }}
  .threat-head {{
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    justify-content: space-between;
  }}
  .threat-pill {{
    display: inline-block;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.06em;
    padding: 3px 10px;
    border-radius: 999px;
    text-transform: uppercase;
  }}
  .threat-num {{
    font-size: 22px;
    font-weight: 750;
    color: #f8fafc;
  }}
  .threat-bar-track {{
    width: 100%;
    height: 8px;
    background: #1e293b;
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid #334155;
  }}
  .threat-bar-fill {{
    height: 100%;
    border-radius: 999px;
  }}
  .action-banner {{
    background: rgba(15, 23, 42, 0.78);
    border-top: 1px solid #334155;
    padding: 12px 0;
  }}
  .action-inner {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px 20px;
  }}
  .action-left {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    flex: 1 1 520px;
  }}
  .action-pill {{
    display: inline-block;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 4px 10px;
    border-radius: 6px;
    white-space: nowrap;
  }}
  .action-text {{
    font-size: 13px;
    color: #e2e8f0;
    font-weight: 500;
  }}
  .action-right {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    font-size: 12px;
    color: #cbd5e1;
    align-items: center;
  }}
  .action-sep {{ color: #475569; }}
  main {{ padding: 22px 0 48px 0; }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
  }}
  .kpi-card {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 15px 16px;
  }}
  .kpi-label {{ font-size: 11.5px; color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }}
  .kpi-val {{ font-size: 25px; font-weight: 750; margin: 4px 0; color: var(--ink); }}
  .kpi-sub {{ font-size: 12px; color: var(--muted); }}
  .exec-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .panel {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 20px;
  }}
  .baseline-panel {{
    background: #f8fafc;
    border: 1px solid #cbd5e1;
  }}
  .baseline-strip {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }}
  .baseline-chip {{
    display: flex;
    align-items: center;
    gap: 8px;
    background: #ffffff;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 7px 11px;
    font-size: 12.5px;
    font-weight: 600;
  }}
  .panel h2 {{
    margin: 0 0 12px 0;
    font-size: 15.5px;
    font-weight: 700;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }}
  .owner-subhead {{
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #334155;
    margin: 10px 0 6px 0;
  }}
  .owner-subhead:first-of-type {{ margin-top: 2px; }}
  ul.brief-list {{ margin: 0; padding-left: 18px; }}
  ul.brief-list li {{ margin-bottom: 7px; }}
  .findings-group {{ margin-bottom: 20px; }}
  .group-heading {{
    font-size: 15px;
    font-weight: 700;
    color: #1e293b;
    margin: 0 0 10px 0;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--line);
  }}
  .finding-card {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 15px 18px;
    margin-bottom: 12px;
  }}
  .finding-top {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }}
  .finding-badges, .owasp-row {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
  .sev-badge {{
    font-size: 11px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 999px;
    letter-spacing: 0.04em;
  }}
  .axis-badge {{
    font-size: 10.5px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 6px;
    letter-spacing: 0.04em;
  }}
  .axis-fp {{ background: #e0e7ff; color: #3730a3; border: 1px solid #c7d2fe; }}
  .axis-ext {{ background: #ffe4e6; color: #9f1239; border: 1px solid #fecdd3; }}
  .vec-badge {{
    font-size: 11px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 6px;
    background: #0f172a;
    color: #f8fafc;
  }}
  .label-badge {{
    font-size: 12px;
    font-weight: 600;
    color: #334155;
    background: #f1f5f9;
    padding: 2px 8px;
    border-radius: 6px;
  }}
  .pill {{
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 6px;
    white-space: nowrap;
  }}
  .owasp-pill {{ background: #eef2ff; color: #3730a3; border: 1px solid #c7d2fe; }}
  .ok-pill {{ background: #dcfce7; color: #166534; }}
  .warn-pill {{ background: #ffedd5; color: #9a3412; }}
  .crit-pill {{ background: #fee2e2; color: #991b1b; }}
  .neutral-pill {{ background: #f1f5f9; color: #334155; }}
  .finding-title {{ margin: 4px 0 6px 0; font-size: 15px; font-weight: 700; }}
  .finding-summary {{ margin: 0 0 10px 0; color: #334155; }}
  .finding-rec {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 13px;
    margin-bottom: 10px;
  }}
  details.ev-drawer summary {{
    cursor: pointer;
    font-weight: 600;
    font-size: 13px;
    color: var(--accent);
    user-select: none;
  }}
  .ev-list {{ margin-top: 10px; display: flex; flex-direction: column; gap: 8px; }}
  .ev-item {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px 12px;
  }}
  .ev-head {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 4px; }}
  .ev-src {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    background: #e2e8f0;
    color: #1e293b;
    padding: 1px 6px;
    border-radius: 4px;
  }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    background: #f1f5f9;
    padding: 1px 4px;
    border-radius: 4px;
    word-break: break-all;
  }}
  .hero code, pre code {{ background: transparent; padding: 0; }}
  .ev-detail {{ font-size: 13px; color: #1e293b; }}
  details.ev-raw {{ margin-top: 6px; }}
  details.ev-raw summary {{ font-size: 11px; color: var(--muted); cursor: pointer; }}
  pre {{
    margin: 6px 0 0 0;
    background: #0f172a;
    color: #e2e8f0;
    padding: 10px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 11px;
    line-height: 1.4;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
  th {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); background: #f8fafc; }}
  .num-cell {{ text-align: right; white-space: nowrap; }}
  .muted {{ color: var(--muted); }}
  .empty-state {{
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
    padding: 16px;
    border-radius: 10px;
    font-weight: 600;
  }}
  footer {{
    border-top: 1px solid var(--line);
    padding: 18px 0 32px 0;
    color: var(--muted);
    font-size: 12px;
  }}
  @media print {{
    body {{ background: #ffffff; }}
    .hero, .action-banner {{ background: #0f172a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .panel, .finding-card, .kpi-card {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<header class="hero">
  <div class="wrap hero-grid">
    <div class="hero-id">
      <div class="eyebrow">agent-perimeter · 2-Axis External Agentic Exposure Audit</div>
      <h1>{_e(domain)}</h1>
      <div class="meta-line">
        <span>Brand Token: <strong>{_e(brand)}</strong></span>
        <span>Verified First-Party Domains: <strong>{_e(", ".join(siblings))}</strong></span>
        <span>Scanned: <strong>{_e(data.get("scanned_at"))}</strong> ({_e(data.get("duration_seconds"))}s)</span>
        <span>Mode: <strong>100% Passive Read-Only</strong></span>
      </div>
    </div>

    <div class="scoreboard" aria-label="2-Axis Executive Scoreboard">
      <div class="axis-card">
        {_posture_ring_svg(posture_score, posture_grade, posture_applicable)}
        <div>
          <div class="axis-kicker">Axis 1 · First-Party Control Posture</div>
          <div class="axis-status">{_e(posture_status_line)}</div>
          <div class="axis-caption">Controllable by Engineering, IAM &amp; DNS</div>
        </div>
      </div>

      <div class="axis-card axis-card-threat">
        <div class="axis-kicker">Axis 2 · External Threat Pressure</div>
        <div class="threat-head">
          <span class="threat-pill" style="background:{threat_pill_bg};color:{threat_pill_fg};border:1px solid {threat_accent};">{_e(threat_level)}</span>
          <span class="threat-num">{threat_score}<span style="font-size:13px;color:#94a3b8;font-weight:600;">/100</span></span>
        </div>
        <div class="threat-bar-track" aria-label="External Threat Pressure {threat_score} out of 100">
          <div class="threat-bar-fill" style="width:{max(0, min(100, threat_score))}%;background:{threat_accent};"></div>
        </div>
        <div class="axis-caption">Third-Party Brand &amp; Supply-Chain Gravity</div>
      </div>
    </div>
  </div>

  <div class="action-banner">
    <div class="wrap action-inner">
      <div class="action-left">
        <span class="action-pill" style="background:{action_bg};color:{action_fg};">{_e(action_posture)}</span>
        <span class="action-text">{_e(action_summary)}</span>
      </div>
      <div class="action-right">
        <span>First-Party Gaps: <strong>{axis_counts.get("first_party_control", len(fp_findings))}</strong></span>
        <span class="action-sep">·</span>
        <span>External Threats: <strong>{axis_counts.get("external_threat", len(ext_findings))}</strong></span>
        <span class="action-sep">|</span>
        <span>Crit: <strong>{sev_counts.get("critical", 0)}</strong></span>
        <span>High: <strong>{sev_counts.get("high", 0)}</strong></span>
        <span>Med: <strong>{sev_counts.get("medium", 0)}</strong></span>
        <span>Low/Info: <strong>{sev_counts.get("low", 0) + sev_counts.get("info", 0)}</strong></span>
      </div>
    </div>
  </div>
</header>

<main class="wrap">
  <section class="kpi-grid" aria-label="Key Exposure Metrics">
    <div class="kpi-card">
      <div class="kpi-label">V1 · Official vs. 3P Proxies</div>
      <div class="kpi-val">{v1_reg.get("official_count", 0)} / {v1_reg.get("unverified_3p_hosted_proxy_count", 0)}</div>
      <div class="kpi-sub">Official MCP Registry entries vs. unverified 3P hosted proxies</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">V1 · Unverified Packages</div>
      <div class="kpi-val">{unv_pkg_cnt}</div>
      <div class="kpi-sub">{_plural(free_email_cnt, "package")} with free-email maintainer(s) (npm + PyPI)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">V2 · Active MCP Endpoints</div>
      <div class="kpi-val">{v2_flags.get("live_mcp_endpoint_count", 0)}</div>
      <div class="kpi-sub">RFC 9728 present: {v2_flags.get("rfc9728_present_count", 0)} · DNS-AID: {"Yes" if v2_dns_aid.get("dns_aid_present") else "No"} · DNSSEC: {"AD=true" if v2_dns_aid.get("apex_dnssec_ad") else "AD=false"}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">V3 · Active Lookalike Sub-Check</div>
      <div class="kpi-val">{v3_active_cnt}</div>
      <div class="kpi-sub">{_e(v3_status)}</div>
    </div>
  </section>

  {control_panel_html}

  <section class="exec-grid">
    <div class="panel" style="margin-bottom:0;">
      <h2>30-Second Executive Brief</h2>
      <ul class="brief-list">{takeaways_html}</ul>
    </div>
    <div class="panel" style="margin-bottom:0;">
      <h2>Prioritized Action Plan (Split by Owner)</h2>
      <div class="owner-subhead">First-Party Controls (AppSec / IAM / DNS)</div>
      <ul class="brief-list">{fp_prios_html}</ul>
      <div class="owner-subhead">External Ecosystem Defense (Brand Protection / Governance)</div>
      <ul class="brief-list">{ext_prios_html}</ul>
    </div>
  </section>

  <section style="margin-bottom: 26px;">
    <h2 style="font-size: 18px; margin: 0 0 12px 0;">Prioritized Findings ({len(findings)})</h2>
    {findings_html}
  </section>

  <section class="panel">
    <h2>V1 · Official MCP Registry Provenance Map <span class="muted" style="font-size:12px;">({v1_reg.get("noise_filtered_count", 0)} generic/homonym entries filtered)</span></h2>
    <table>
      <thead><tr><th>Server Identifier</th><th>Provenance Classification</th><th>Remote Endpoint(s)</th></tr></thead>
      <tbody>{reg_table_body}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>V1 · Brand-Named MCP Packages (npm &amp; PyPI)</h2>
    <table>
      <thead><tr><th>Registry</th><th>Package</th><th>Provenance</th><th>Monthly Downloads</th><th>Maintainer Email Domain</th></tr></thead>
      <tbody>{pkg_table_body}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>V2 · External Agentic Perimeter, DNS-AID &amp; OAuth Hygiene</h2>
    <p class="muted" style="margin-top:0;">
      CT Provider: <strong>{_e(v2_flags.get("ct_provider_used") or "none")}</strong> ·
      Apex DNSSEC: <strong>{"Validated (AD=true)" if v2_dns_aid.get("apex_dnssec_ad") else "Not Validated (AD=false)"}</strong> ·
      DNS-AID (<code>_agent</code>/<code>_mcp</code>): <strong>{"Present" if v2_dns_aid.get("dns_aid_present") else "Not Detected"}</strong>
    </p>
    <table>
      <thead><tr><th>Live Hostname</th><th>Confirmed MCP</th><th>Passive HTTP (/ , /mcp)</th><th>RFC 9728 OAuth Metadata</th><th>DNSSEC</th></tr></thead>
      <tbody>{sub_table_body}</tbody>
    </table>
  </section>
</main>

<footer class="wrap">
  <p><strong>Methodology &amp; Neutrality Notice:</strong> Generated by <code>agent-perimeter</code> v{_e(data.get("tool_version"))} (scoring model <code>{_e(score.get("scoring_model") or "2-axis-v1")}</code>) using 100% passive, read-only public APIs, DNS-over-HTTPS, Certificate Transparency, and standard discovery endpoints. <strong>External Threat Pressure</strong> measures third-party ecosystem activity and brand gravity rather than first-party security negligence. Classifications such as <em>Unverified 3rd-Party Hosted Proxy</em> or <em>Unverified Package / Free-Email Maintainer</em> describe verifiable provenance properties and do not imply malicious intent by commercial aggregators or community maintainers. <em>Phishing-Warning Lookalike Domain</em> classifications reflect passively observed third-party warning interstitials requiring independent ownership and status verification before enforcement. Findings map to OWASP Top 10 for Agentic Applications (2026 v1.0) and OWASP MCP Top 10 (2025 v0.1 Beta).</p>
</footer>
</body>
</html>
"""
