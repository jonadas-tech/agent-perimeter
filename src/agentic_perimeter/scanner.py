"""Main passive audit orchestrator for single-domain and batch cohort scans."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .dns_ct import (
    discover_sibling_domains,
    registrable_domain,
    url_host,
)
from .http_client import PoliteHttpClient
from .models import AuditReport, BrandTarget
from .rdap import enrich_report_rdap
from .scoring import score_audit, sort_findings
from .static_audit import inspect_npm_package_static, inspect_pypi_package_static
from .vector1_supply_chain import probe_vector1
from .vector2_perimeter import _extract_declared_endpoints, _parse_json_discovery, probe_vector2
from .vector3_lookalike import probe_vector3

SCHEMA_VERSION = "2.0"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_target(
    domain: str,
    brand: Optional[str] = None,
    aliases: Optional[List[str]] = None,
    sector: str = "Unknown",
    cohort: str = "custom",
    exclude_terms: Optional[List[str]] = None,
    known_sibling_domains: Optional[List[str]] = None,
) -> BrandTarget:
    """Normalize a raw domain or URL into a clean BrandTarget."""
    clean = domain.strip().lower()
    if "://" in clean:
        clean = url_host(clean)
    clean = clean.split("/", 1)[0].split(":", 1)[0]
    if clean.startswith("www."):
        clean = clean[4:]
    primary = registrable_domain(clean) or clean
    if not primary or "." not in primary:
        raise ValueError(f"Invalid target domain: {domain!r}")

    inferred_brand = (brand or primary.split(".")[0]).strip().lower()
    # Strip trailing 'hq' for cleaner default brand token (e.g., datadoghq.com -> datadog)
    alias_list = list(aliases or [])
    if not brand and inferred_brand.endswith("hq") and len(inferred_brand) > 4:
        alias_list.append(inferred_brand)
        inferred_brand = inferred_brand[:-2]

    return BrandTarget(
        domain=primary,
        brand=inferred_brand,
        aliases=alias_list,
        sector=sector,
        cohort=cohort,
        exclude_terms=list(exclude_terms or []),
        known_sibling_domains=list(known_sibling_domains or []),
    )


def _peek_well_known_siblings(
    client: PoliteHttpClient,
    primary: str,
    aliases: List[str],
) -> List[str]:
    """Quickly inspect root /.well-known/mcp.json & agent.json for verified sibling brand domains
    (e.g., notion.so -> mcp.notion.com, sentry.io -> mcp.sentry.dev) before running Vector 1.
    """
    siblings: List[str] = []
    alias_lows = [a.lower() for a in aliases if len(a) >= 3]
    for path in ("/.well-known/mcp.json", "/.well-known/agent.json"):
        resp = client.get(f"https://{primary}{path}", timeout=5.0, max_bytes=65536, retries=0)
        ok, parsed, _ = _parse_json_discovery(resp)
        if not (ok and parsed):
            continue
        for ep_url in _extract_declared_endpoints(parsed):
            h = url_host(ep_url)
            if not h:
                continue
            reg = registrable_domain(h)
            if reg and reg != primary and any(a in reg.split(".")[0] for a in alias_lows):
                if reg not in siblings:
                    siblings.append(reg)
    return siblings


def _run_optional_static_package_audit(
    client: PoliteHttpClient,
    target: BrandTarget,
    v1_data: Dict[str, Any],
    max_packages: int = 10,
) -> Dict[str, Any]:
    """Passively inspect top unverified npm/PyPI packages strictly in memory (zero execution)."""
    candidates: List[tuple[str, str]] = []
    for p in (v1_data.get("npm") or {}).get("packages") or []:
        if not p.get("official_anchored") and p.get("name"):
            candidates.append(("npm", str(p["name"])))
    for p in (v1_data.get("pypi") or {}).get("packages") or []:
        if not p.get("official_anchored") and p.get("name"):
            candidates.append(("pypi", str(p["name"])))
    chosen = candidates[:max_packages]
    inspected: List[Dict[str, Any]] = []
    for reg, name in chosen:
        if reg == "npm":
            inspected.append(inspect_npm_package_static(client, name, target.brand))
        else:
            inspected.append(inspect_pypi_package_static(client, name, target.brand))
    ok_rows = [r for r in inspected if r.get("ok")]
    return {
        "enabled": True,
        "inspected_count": len(ok_rows),
        "attempted_count": len(chosen),
        "unverified_remote_postinstall_count": sum(
            1 for r in ok_rows if (r.get("signals") or {}).get("unverified_remote_postinstall")
        ),
        "dormant_placeholder_stub_count": sum(
            1 for r in ok_rows if (r.get("signals") or {}).get("dormant_placeholder_stub")
        ),
        "unrelated_cli_bin_shadowing_count": sum(
            1 for r in ok_rows if (r.get("signals") or {}).get("unrelated_cli_bin_shadowing")
        ),
        "packages": inspected,
    }


def audit_target(
    target: BrandTarget,
    client: Optional[PoliteHttpClient] = None,
    gh_cache: Optional[Dict[str, Dict[str, Any]]] = None,
    include_lookalike: bool = True,
    inspect_packages: bool = False,
    enable_rdap: bool = True,
) -> AuditReport:
    """Execute a complete 100% passive audit on a single BrandTarget."""
    t0 = time.monotonic()
    http = client or PoliteHttpClient()
    cache = gh_cache if gh_cache is not None else {}

    # 1. Discover verified sibling domains passively
    verified_domains, sibling_evidence = discover_sibling_domains(
        http,
        target.domain,
        target.brand,
        target.normalized_aliases(),
        seed_siblings=target.known_sibling_domains,
    )
    wk_siblings = _peek_well_known_siblings(http, target.domain, target.normalized_aliases())
    for s in wk_siblings:
        if s not in verified_domains:
            verified_domains.append(s)
    verified_domains = sorted(set(verified_domains))

    # 2. Vector 1 (Primary): MCP Supply-Chain & Brand Provenance
    v1_data, v1_findings = probe_vector1(http, target, verified_domains, cache)
    if inspect_packages:
        v1_data["static_package_audit"] = _run_optional_static_package_audit(http, target, v1_data)

    # 3. Vector 2 (Secondary Hardened): External Perimeter, DNS-AID, CT/TLS SAN & OAuth
    v2_data, v2_findings, v2_siblings = probe_vector2(http, target, verified_domains, v1_data=v1_data)
    for s in v2_siblings:
        if s not in verified_domains:
            verified_domains.append(s)
    verified_domains = sorted(set(verified_domains))

    # 4. Vector 3 (Demoted Silent Sub-Check): Active Lookalike MCP / Phishing Only
    if include_lookalike:
        v3_data, v3_findings = probe_vector3(http, target, verified_domains)
    else:
        v3_data = {
            "skipped": True,
            "reason": "disabled_by_flag",
            "permutations_tested": 0,
            "active_agent_endpoints": [],
            "phishing_flagged": [],
            "spoofed_ans_badge_hosts": [],
            "flags": {
                "has_active_lookalike_agent_endpoint": False,
                "has_active_phishing_lookalike": False,
                "has_spoofed_ans_badge_lookalike": False,
            },
        }
        v3_findings = []

    # 5. Passive RFC 9083 RDAP enrichment for 3P proxy & lookalike domains (bounded, graceful fallback)
    if enable_rdap:
        rdap_summary = enrich_report_rdap(http, v1_data, v3_data, max_domains=15, v2_data=v2_data)
    else:
        rdap_summary = {
            "enabled": False,
            "queried_count": 0,
            "resolved_count": 0,
            "nod_30d_count": 0,
            "nod_90d_count": 0,
            "nod_30d_domains": [],
            "nod_90d_domains": [],
            "domains": {},
        }

    all_findings = sort_findings([*v1_findings, *v2_findings, *v3_findings])
    score = score_audit(target, all_findings, v1_data, v2_data, v3_data)
    duration = time.monotonic() - t0

    return AuditReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        scanned_at=utc_now_iso(),
        duration_seconds=duration,
        target=target,
        verified_sibling_domains=verified_domains,
        score=score,
        findings=all_findings,
        vector1=v1_data,
        vector2=v2_data,
        vector3=v3_data,
        telemetry={
            "sibling_discovery": sibling_evidence,
            "github_authenticated": bool(http.github_token),
            "certspotter_authenticated": bool(http.certspotter_token),
            "rdap": rdap_summary,
        },
    )


def audit_domain(
    domain: str,
    brand: Optional[str] = None,
    aliases: Optional[List[str]] = None,
    include_lookalike: bool = True,
    enable_github_search: bool = True,
    inspect_packages: bool = False,
    enable_rdap: bool = True,
) -> AuditReport:
    target = normalize_target(domain=domain, brand=brand, aliases=aliases)
    client = PoliteHttpClient(enable_github_search=enable_github_search)
    return audit_target(
        target,
        client=client,
        include_lookalike=include_lookalike,
        inspect_packages=inspect_packages,
        enable_rdap=enable_rdap,
    )


def load_targets_from_json(path: str) -> List[BrandTarget]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    items = raw.get("brands", raw) if isinstance(raw, dict) else raw
    targets: List[BrandTarget] = []
    for row in items:
        if isinstance(row, str):
            targets.append(normalize_target(row))
        elif isinstance(row, dict):
            targets.append(
                normalize_target(
                    domain=row["domain"],
                    brand=row.get("brand"),
                    aliases=row.get("aliases"),
                    sector=row.get("sector", "Unknown"),
                    cohort=row.get("cohort", "custom"),
                    exclude_terms=row.get("exclude_terms"),
                    known_sibling_domains=row.get("known_sibling_domains"),
                )
            )
    return targets


def audit_batch(
    targets: List[BrandTarget],
    workers: int = 6,
    include_lookalike: bool = True,
    enable_github_search: bool = True,
    enable_rdap: bool = True,
    on_complete: Optional[Callable[[int, int, AuditReport], None]] = None,
) -> Dict[str, Any]:
    """Run polite concurrent passive audits across a cohort of BrandTargets."""
    t0 = time.monotonic()
    started_at = utc_now_iso()
    client = PoliteHttpClient(enable_github_search=enable_github_search)
    gh_cache: Dict[str, Dict[str, Any]] = {}
    results_by_domain: Dict[str, Dict[str, Any]] = {}
    errors: Dict[str, str] = {}
    completed = 0
    total = len(targets)

    def _run_one(tgt: BrandTarget) -> AuditReport:
        return audit_target(
            tgt,
            client=client,
            gh_cache=gh_cache,
            include_lookalike=include_lookalike,
            enable_rdap=enable_rdap,
        )

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        fut_map = {pool.submit(_run_one, t): t for t in targets}
        for fut in as_completed(fut_map):
            tgt = fut_map[fut]
            completed += 1
            try:
                rep = fut.result()
                results_by_domain[tgt.domain] = rep.to_dict()
                if on_complete:
                    on_complete(completed, total, rep)
            except Exception as exc:
                errors[tgt.domain] = f"{type(exc).__name__}: {exc}"
                print(
                    f"[{utc_now_iso()}] ERROR {completed}/{total} {tgt.domain}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )

    # Preserve canonical target ordering
    ordered_reports = [
        results_by_domain[t.domain] for t in targets if t.domain in results_by_domain
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "started_at": started_at,
        "finished_at": utc_now_iso(),
        "duration_seconds": round(time.monotonic() - t0, 2),
        "total_targets": total,
        "completed_targets": len(ordered_reports),
        "errors": errors,
        "api_stats": client.stats,
        "reports": ordered_reports,
    }
