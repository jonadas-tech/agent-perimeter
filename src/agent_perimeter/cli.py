"""Command-line interface for agent-perimeter (uvx-ready)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from . import __version__
from .diff import compare_reports, format_diff_summary
from .dns_policy import render_domain_feed, render_rpz
from .report_html import render_html_report
from .sarif import render_sarif
from .scanner import audit_batch, audit_domain, load_targets_from_json, utc_now_iso
from .study import anonymize_batch_results, render_study_markdown
from .trend import compute_trend, render_trend_markdown


def _write_text(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _format_posture_str(sc: dict) -> str:
    if sc.get("control_posture_applicable") and sc.get("control_posture_score") is not None:
        return f"{sc['control_posture_grade']} ({sc['control_posture_score']}/100 - {sc['control_posture_label']})"
    return "N/A (Baseline)"


def _print_console_summary(report_dict: dict) -> None:
    tgt = report_dict["target"]
    sc = report_dict["score"]
    findings = report_dict["findings"]
    v1_reg = report_dict["vector1"]["mcp_registry"]
    v2_flags = report_dict["vector2"]["flags"]

    posture_str = _format_posture_str(sc)
    threat_str = f"{sc['threat_pressure_level']} ({sc['threat_pressure_score']}/100)"
    action_str = sc.get("action_posture", "Baseline — Monitor")

    print(
        f"\nagent-perimeter v{__version__} | {tgt['domain']} (brand: {tgt['brand']}) | {report_dict['duration_seconds']}s"
    )
    print(
        f"Control Posture: {posture_str} | Threat Pressure: {threat_str} | Action: {action_str}"
    )
    print(
        f"V1 MCP Registry: {v1_reg['official_count']} official | "
        f"{v1_reg['unverified_3p_hosted_proxy_count']} unverified 3P proxies | "
        f"{v1_reg['url_path_token_exposed_count']} URL-path token exposed"
    )
    print(
        f"V2 Perimeter: {v2_flags['live_mcp_endpoint_count']} live MCP endpoint(s) | "
        f"RFC 9728 present: {v2_flags['rfc9728_present_count']} | "
        f"DNS-AID: {'yes' if v2_flags['dns_aid_present'] else 'no'} | "
        f"DNSSEC: {'AD=true' if v2_flags['apex_dnssec_enabled'] else 'AD=false'}"
    )
    if (
        v2_flags.get("dns_aid_agent_count")
        or v2_flags.get("dane_tlsa_present")
        or v2_flags.get("ans_badge_present")
        or v2_flags.get("spoofed_ans_badge_count")
        or v2_flags.get("chain_of_trust_surfaces")
    ):
        cot = ", ".join(v2_flags.get("chain_of_trust_surfaces") or []) or "none"
        print(
            f"V2 Wire DNS-AID/ANS: {v2_flags.get('dns_aid_agent_count', 0)} agent(s) | "
            f"cap-sha256 ok/mismatch: {v2_flags.get('dns_aid_card_hash_verified_count', 0)}/"
            f"{v2_flags.get('dns_aid_card_hash_mismatch_count', 0)} | "
            f"DANE TLSA: {v2_flags.get('dane_tlsa_count', 0)} | "
            f"ANS badge ok/spoofed: {v2_flags.get('ans_badge_verified_count', 0)}/"
            f"{v2_flags.get('spoofed_ans_badge_count', 0)} | "
            f"Chain-of-Trust: {cot}"
        )
    rdap_tel = (report_dict.get("telemetry") or {}).get("rdap") or {}
    if rdap_tel.get("queried_count"):
        print(
            f"RDAP Passive Profiling: {rdap_tel.get('resolved_count', 0)}/{rdap_tel.get('queried_count', 0)} resolved | "
            f"NOD <30d: {rdap_tel.get('nod_30d_count', 0)} | NOD <90d: {rdap_tel.get('nod_90d_count', 0)}"
        )
    print(f"\nFindings ({len(findings)}):")
    if not findings:
        print("  - None (no passive exposure signals triggered)")
    for f in findings:
        owasp_codes = ", ".join(o["code"] for o in f["owasp"])
        axis_tag = "1P" if f.get("axis") == "first_party_control" else "3P"
        print(f"  [{f['severity'].upper():8s}] ({f['vector']}/{axis_tag}) {f['label']}: {f['title']} [{owasp_codes}]")


def _cmd_audit(args: argparse.Namespace) -> int:
    audit_kwargs = {
        "domain": args.domain,
        "brand": args.brand,
        "aliases": args.alias or [],
        "include_lookalike": not args.no_lookalike,
        "enable_github_search": not args.no_github_search,
    }
    if getattr(args, "inspect_packages", False):
        audit_kwargs["inspect_packages"] = True
    if getattr(args, "no_rdap", False):
        audit_kwargs["enable_rdap"] = False
    report = audit_domain(**audit_kwargs)
    report_dict = report.to_dict()

    diff_result = None
    if getattr(args, "baseline", None):
        with open(args.baseline, "r", encoding="utf-8") as bf:
            baseline_dict = json.load(bf)
        diff_result = compare_reports(report_dict, baseline_dict)
        report_dict["baseline_diff"] = diff_result

    rpz_mode = getattr(args, "rpz_mode", "block") or "block"
    rpz_path = getattr(args, "rpz", None)
    feed_path = getattr(args, "domain_feed", None)

    if args.json:
        _write_text(args.json, json.dumps(report_dict, indent=2, ensure_ascii=False))
    if args.html:
        _write_text(args.html, render_html_report(report_dict))
    if getattr(args, "sarif", None):
        _write_text(args.sarif, json.dumps(render_sarif(report_dict), indent=2, ensure_ascii=False))
    if rpz_path:
        _write_text(rpz_path, render_rpz(report_dict, policy_mode=rpz_mode))
    if feed_path:
        _write_text(feed_path, json.dumps(render_domain_feed(report_dict, policy_mode=rpz_mode), indent=2, ensure_ascii=False))

    any_file_out = bool(args.json or args.html or getattr(args, "sarif", None) or rpz_path or feed_path)
    if not args.quiet:
        _print_console_summary(report_dict)
        if diff_result is not None:
            print("")
            for line in format_diff_summary(diff_result):
                print(line)
        if args.json:
            print(f"\nJSON report written to: {args.json}")
        if args.html:
            print(f"HTML report written to: {args.html}")
        if getattr(args, "sarif", None):
            print(f"SARIF 2.1.0 report written to: {args.sarif}")
        if rpz_path:
            print(f"Protective DNS RPZ ({rpz_mode}) written to: {rpz_path}")
        if feed_path:
            print(f"Protective DNS domain feed written to: {feed_path}")
    elif not any_file_out:
        print(json.dumps(report_dict, indent=2, ensure_ascii=False))

    if getattr(args, "fail_on_new", False) and diff_result and diff_result.get("has_new_exposures"):
        return 2
    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    targets = load_targets_from_json(args.targets)
    if args.limit and args.limit > 0:
        targets = targets[: args.limit]

    def _progress(done: int, total: int, rep) -> None:
        if not args.quiet:
            sc = rep.score
            posture_val = f"{sc.control_posture_grade}({sc.control_posture_score:3d})" if sc.control_posture_score is not None else "N/A    "
            print(
                f"[{utc_now_iso()}] {done:3d}/{total} {rep.target.domain:24s} "
                f"posture={posture_val} threat={sc.threat_pressure_score:3d}({sc.threat_pressure_level:8s}) "
                f"action={sc.action_posture} ({rep.duration_seconds:.1f}s)",
                file=sys.stderr,
                flush=True,
            )

    batch_data = audit_batch(
        targets,
        workers=args.workers,
        include_lookalike=not args.no_lookalike,
        enable_github_search=not args.no_github_search,
        enable_rdap=not getattr(args, "no_rdap", False),
        on_complete=_progress,
    )
    _write_text(args.output, json.dumps(batch_data, indent=2, ensure_ascii=False))

    if args.anonymized_out or args.study_md:
        study = anonymize_batch_results(batch_data)
        if args.anonymized_out:
            _write_text(args.anonymized_out, json.dumps(study, indent=2, ensure_ascii=False))
        if args.study_md:
            _write_text(args.study_md, render_study_markdown(study))

    if not args.quiet:
        print(
            f"\nBatch complete: {batch_data['completed_targets']}/{batch_data['total_targets']} targets "
            f"in {batch_data['duration_seconds']}s -> {args.output}"
        )
    return 0


def _cmd_summarize(args: argparse.Namespace) -> int:
    with open(args.input, "r", encoding="utf-8") as f:
        batch_data = json.load(f)
    study = anonymize_batch_results(batch_data)
    if args.anonymized_out:
        _write_text(args.anonymized_out, json.dumps(study, indent=2, ensure_ascii=False))
    if args.study_md:
        _write_text(args.study_md, render_study_markdown(study))
    if not args.anonymized_out and not args.study_md:
        print(render_study_markdown(study))
    return 0


def _cmd_trend(args: argparse.Namespace) -> int:
    with open(args.previous, "r", encoding="utf-8") as fp:
        prev_data = json.load(fp)
    with open(args.current, "r", encoding="utf-8") as fc:
        curr_data = json.load(fc)

    trend_dict = compute_trend(
        prev_data,
        curr_data,
        label_prev=args.label_prev,
        label_curr=args.label_curr,
    )
    md_out = render_trend_markdown(trend_dict)

    if args.json:
        _write_text(args.json, json.dumps(trend_dict, indent=2, ensure_ascii=False))
    if args.md:
        _write_text(args.md, md_out)
    if not args.json and not args.md:
        print(md_out)
    elif not getattr(args, "quiet", False):
        ov = trend_dict["cohort_overlap"]
        print(
            f"Trend computed ({trend_dict['labels']['previous']} -> {trend_dict['labels']['current']}): "
            f"{ov['matched_count']} matched | {ov['added_count']} added | {ov['removed_count']} removed"
        )
        if args.json:
            print(f"Trend JSON written to: {args.json}")
        if args.md:
            print(f"Trend Markdown written to: {args.md}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-perimeter",
        description=(
            "100% passive external attack surface scanner for agentic brand impersonation, "
            "MCP supply-chain exposure, and DNS-AID/OAuth perimeter hygiene."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agent-perimeter {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # audit
    p_audit = sub.add_parser("audit", help="Run a passive external agentic exposure audit on a single domain.")
    p_audit.add_argument("domain", help="Target domain (e.g. stripe.com)")
    p_audit.add_argument("--brand", help="Optional explicit brand token override")
    p_audit.add_argument("--alias", action="append", help="Additional brand alias (repeatable)")
    p_audit.add_argument("--json", help="Path to export structured JSON report")
    p_audit.add_argument("--html", help="Path to export single-file CISO HTML report")
    p_audit.add_argument("--sarif", help="Path to export SARIF 2.1.0 report for GitHub Code Scanning / CI")
    p_audit.add_argument("--rpz", help="Path to export open-standard Protective DNS RPZ zone file")
    p_audit.add_argument("--domain-feed", help="Path to export structured Protective DNS JSON domain feed")
    p_audit.add_argument(
        "--rpz-mode",
        choices=["block", "audit"],
        default="block",
        help="RPZ/feed enforcement mode for high-confidence risk indicators (default: block)",
    )
    p_audit.add_argument("--baseline", help="Path to a previous JSON report to diff for new external exposures")
    p_audit.add_argument("--fail-on-new", action="store_true", help="Exit with code 2 if --baseline detects new exposures")
    p_audit.add_argument("--inspect-packages", action="store_true", help="Passively inspect up to 10 unverified npm/PyPI tarballs in memory (zero execution)")
    p_audit.add_argument("--no-lookalike", action="store_true", help="Skip V3 active lookalike sub-check")
    p_audit.add_argument("--no-github-search", action="store_true", help="Skip GitHub repo search in V1")
    p_audit.add_argument("--no-rdap", action="store_true", help="Skip passive RFC 9083 RDAP domain-age/registrar enrichment")
    p_audit.add_argument("--quiet", "-q", action="store_true", help="Suppress console summary output")
    p_audit.set_defaults(func=_cmd_audit)

    # batch
    p_batch = sub.add_parser("batch", help="Run polite concurrent passive audits across a JSON list of brands.")
    p_batch.add_argument("targets", help="Path to targets JSON file")
    p_batch.add_argument("--output", "-o", required=True, help="Path to write full raw JSON batch output")
    p_batch.add_argument("--workers", type=int, default=6, help="Concurrent workers (default: 6)")
    p_batch.add_argument("--limit", type=int, default=0, help="Optional limit on number of targets to scan")
    p_batch.add_argument("--anonymized-out", help="Optional path to export anonymized study JSON")
    p_batch.add_argument("--study-md", help="Optional path to export anonymized Markdown study summary")
    p_batch.add_argument("--no-lookalike", action="store_true", help="Skip V3 active lookalike sub-check")
    p_batch.add_argument("--no-github-search", action="store_true", help="Skip GitHub repo search (faster for large cohorts)")
    p_batch.add_argument("--no-rdap", action="store_true", help="Skip passive RFC 9083 RDAP domain-age/registrar enrichment")
    p_batch.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    p_batch.set_defaults(func=_cmd_batch)

    # summarize
    p_sum = sub.add_parser("summarize", help="Generate anonymized study JSON & Markdown from a raw batch JSON.")
    p_sum.add_argument("input", help="Path to raw batch JSON file")
    p_sum.add_argument("--anonymized-out", help="Path to export anonymized study JSON")
    p_sum.add_argument("--study-md", help="Path to export Markdown study summary")
    p_sum.set_defaults(func=_cmd_summarize)

    # trend
    p_trend = sub.add_parser(
        "trend",
        help="Compute longitudinal cohort adoption & exposure deltas between two batch or anonymized study JSON files.",
    )
    p_trend.add_argument("previous", help="Path to earlier batch or anonymized study JSON file")
    p_trend.add_argument("current", help="Path to newer batch or anonymized study JSON file")
    p_trend.add_argument("--json", help="Path to write structured trend JSON")
    p_trend.add_argument("--md", help="Path to write Markdown trend report")
    p_trend.add_argument("--label-prev", help="Optional period label for previous dataset (e.g. 2026-Q4)")
    p_trend.add_argument("--label-curr", help="Optional period label for current dataset (e.g. 2027-Q1)")
    p_trend.add_argument("--quiet", "-q", action="store_true", help="Suppress console summary output")
    p_trend.set_defaults(func=_cmd_trend)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
