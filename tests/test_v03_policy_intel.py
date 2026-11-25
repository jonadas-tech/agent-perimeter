"""Deterministic offline unit tests for v0.3.0 policy & intel modules:
- rdap.py (RFC 9083 passive domain-age & registrar profiler)
- dns_policy.py (vendor-neutral RPZ & structured JSON domain feed exporter)
- trend.py (longitudinal cohort diff engine for raw batch & anonymized study JSONs)
- CLI integration (--rpz, --domain-feed, --rpz-mode, --no-rdap, trend subcommand)
- HTML report rendering for wire-level DNS-AID/ANS v2 validation & RDAP NOD badges
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List

import agentic_perimeter
from agentic_perimeter import cli
from agentic_perimeter.dns_policy import (
    is_shared_multitenant_platform,
    render_domain_feed,
    render_rpz,
)
from agentic_perimeter.http_client import HttpResponse
from agentic_perimeter.models import AuditReport, BrandTarget, ScoreSummary
from agentic_perimeter.rdap import (
    clear_rdap_caches,
    enrich_report_rdap,
    lookup_rdap,
    parse_rdap_response,
)
from agentic_perimeter.report_html import render_html_report
from agentic_perimeter.trend import compute_trend, render_trend_markdown


class _MockHttpClient:
    """Minimal deterministic HTTP mock compatible with PoliteHttpClient.get()."""

    def __init__(self, responses: Dict[str, HttpResponse]) -> None:
        self._responses = responses
        self.calls: List[str] = []

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        self.calls.append(url)
        if url in self._responses:
            return self._responses[url]
        return HttpResponse(url=url, final_url=url, status=404, headers={}, body_text="", error="http_404")


def _json_resp(url: str, payload: Any, status: int = 200) -> HttpResponse:
    return HttpResponse(
        url=url,
        final_url=url,
        status=status,
        headers={"content-type": "application/json"},
        body_text=json.dumps(payload),
    )


def _sample_rdap_payload(created: str, registrar: str, status_flags: List[str] | None = None) -> Dict[str, Any]:
    return {
        "objectClassName": "domain",
        "ldhName": "example.dev",
        "status": status_flags or ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": created},
            {"eventAction": "last changed", "eventDate": "2026-11-20T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-11-10T00:00:00Z"},
        ],
        "entities": [
            {
                "objectClassName": "entity",
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", registrar],
                    ],
                ],
            }
        ],
    }


def _make_rich_v03_report(domain: str = "agenthaven.dev", include_spoof: bool = False) -> Dict[str, Any]:
    agent_host = f"travel.{domain}"
    spoof_list = (
        [
            {
                "host": agent_host,
                "receipt_host": "travel.realbrand.dev",
                "ans_name": "ans://v0.1.0.travel.realbrand.dev",
                "receipt_url": "https://transparency.example/v1/agents/uuid-1",
                "receipt_status": "ACTIVE",
                "dnssec_ad": True,
            }
        ]
        if include_spoof
        else []
    )
    ans_badge = (
        {
            "present": True,
            "host": agent_host,
            "qname": f"_ans-badge.{agent_host}",
            "dnssec_ad": True,
            "raw_txt": "v=ans-badge1; version=v0.1.0; url=https://transparency.example/v1/agents/uuid-1",
            "version": "v0.1.0",
            "receipt_url": "https://transparency.example/v1/agents/uuid-1",
            "receipt_status": "ACTIVE",
            "ans_name": "ans://v0.1.0.travel.realbrand.dev",
            "receipt_host": "travel.realbrand.dev",
            "host_binding_status": "host_mismatch",
            "spoofed": True,
            "error": None,
        }
        if include_spoof
        else {
            "present": True,
            "host": agent_host,
            "qname": f"_ans-badge.{agent_host}",
            "dnssec_ad": True,
            "raw_txt": "v=ans-badge1; version=v0.1.0; url=https://transparency.example/v1/agents/uuid-2",
            "version": "v0.1.0",
            "receipt_url": "https://transparency.example/v1/agents/uuid-2",
            "receipt_status": "ACTIVE",
            "ans_name": f"ans://v0.1.0.{agent_host}",
            "receipt_host": agent_host,
            "host_binding_status": "verified",
            "spoofed": False,
            "error": None,
        }
    )

    sc = ScoreSummary(
        scoring_model="2-axis-v1",
        control_posture_score=82 if not include_spoof else 45,
        control_posture_grade="B" if not include_spoof else "D",
        control_posture_label="Strong" if not include_spoof else "Weak",
        control_posture_applicable=True,
        control_breakdown=[],
        threat_pressure_score=40,
        threat_pressure_level="Moderate",
        threat_breakdown=[],
        action_posture="Active Monitoring",
        action_posture_summary="Summary",
        counts_by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        counts_by_vector={"V1": 1, "V2": 0, "V3": 0},
        counts_by_axis={"first_party_control": 0, "external_threat": 1},
        ciso_takeaways=["Takeaway"],
        first_party_priorities=[],
        external_defense_priorities=[],
        top_priorities=[],
    )
    rep = AuditReport(
        schema_version="2.0",
        tool_version=agentic_perimeter.__version__,
        scanned_at="2026-11-24T12:00:00Z",
        duration_seconds=1.5,
        target=BrandTarget(domain=domain, brand=domain.split(".")[0], sector="AI & Data", cohort="saas_ai_fintech"),
        verified_sibling_domains=[domain],
        score=sc,
        findings=[],
        vector1={
            "mcp_registry": {
                "official_count": 1,
                "unverified_3p_hosted_proxy_count": 2,
                "url_path_token_exposed_count": 2,
                "entries": [
                    {
                        "name": "io.dedproxy/mcp-brand",
                        "classification": "unverified_3p_hosted_proxy",
                        "url_path_token_exposed": True,
                        "token_exposed_urls": ["https://relay.rogue-proxy.xyz/mcp/{api_key}"],
                        "remote_domains": ["rogue-proxy.xyz"],
                        "remotes": [{"url": "https://relay.rogue-proxy.xyz/mcp/{api_key}"}],
                        "remote_rdap": {
                            "rogue-proxy.xyz": {
                                "ok": True,
                                "age_days": 11,
                                "created_at": "2026-11-13T00:00:00Z",
                                "registrar": "FreshReg <script>alert(1)</script> LLC",
                                "is_nod_30d": True,
                                "is_nod_90d": True,
                            }
                        },
                    },
                    {
                        "name": "ai.smithery/brand-mcp",
                        "classification": "unverified_3p_hosted_proxy",
                        "url_path_token_exposed": True,
                        "token_exposed_urls": ["https://server.smithery.ai/brand/{token}"],
                        "remote_domains": ["smithery.ai"],
                        "remotes": [{"url": "https://server.smithery.ai/brand/{token}"}],
                    },
                    {
                        "name": "app.vercel/community-brand",
                        "classification": "unverified_3p_hosted_proxy",
                        "url_path_token_exposed": False,
                        "remote_domains": ["vercel.app"],
                        "remotes": [{"url": "https://brand-community.vercel.app/mcp"}],
                    },
                ],
            },
            "npm": {"official_count": 1, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
            "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
            "flags": {"has_any_mcp_footprint": True, "official_registry_vacuum": False},
        },
        vector2={
            "dns_aid": {"apex_dnssec_ad": True, "dns_aid_present": True},
            "subdomains": [
                {
                    "fqdn": f"mcp.{domain}",
                    "effectively_live": True,
                    "confirmed_mcp_endpoint": True,
                    "rfc9728": {"scopes_supported": ["read"]},
                    "missing_rfc9728": False,
                    "dnssec_ad": True,
                    "http_root": {"status": 200},
                    "http_mcp": {"status": 401},
                }
            ],
            "dns_aid_linter": {
                "domain": domain,
                "apex_dnssec_ad": True,
                "index_found": True,
                "index_source": "svcb+txt",
                "index_dnssec_ad": True,
                "catalog_separated": True,
                "catalog_host": f"catalog.{domain}",
                "indexed_agents": [{"name": "travel", "protocol": "a2a"}],
                "agent_records": [
                    {
                        "agent_name": "travel",
                        "protocol": "a2a",
                        "qname": agent_host,
                        "target_host": agent_host,
                        "dnssec_ad": True,
                        "svcb": {
                            "priority": 1,
                            "mode": "service",
                            "target": agent_host,
                            "alpn": ["a2a"],
                            "port": 443,
                            "mandatory": ["alpn", "port"],
                            "cap": f"https://{agent_host}/.well-known/agent-card.json",
                            "cap_sha256": "abc123",
                            "bap": ["a2a"],
                            "sig": "eyJhbGciOiJFUzI1NiJ9.x.y",
                        },
                        "card_verification": {"status": "verified", "cap_url": f"https://{agent_host}/.well-known/agent-card.json"},
                        "dane_tlsa": {"present": True, "dnssec_ad": True, "dane_without_dnssec": False, "records": [{"usage": 3}]},
                        "ans_badge": ans_badge,
                    }
                ],
                "verified_first_party_agent_fqdns": [] if include_spoof else [agent_host, f"catalog.{domain}"],
                "card_hash_verified_count": 1,
                "card_hash_mismatch_hosts": [],
                "dane_tlsa_hosts": [agent_host],
                "dane_without_dnssec_hosts": [],
                "ans_badge_verified_hosts": [] if include_spoof else [agent_host],
                "spoofed_ans_badge_hosts": spoof_list,
            },
            "chain_of_trust": {
                "ard": [{"host": domain, "url": f"https://{domain}/.well-known/ard.json", "entries_count": 1}],
                "ucp": [{"host": agent_host, "url": f"https://{agent_host}/.well-known/ucp", "keys_count": 2}],
                "spiffe_bundle": [{"host": agent_host, "keys_count": 1}],
                "spiffe_svid": [{"host": agent_host, "spiffe_id": f"spiffe://{domain}/travel"}],
                "agent_keys_txt": [],
                "surfaces_detected": ["ard", "ucp", "spiffe_bundle", "spiffe_svid"],
            },
            "flags": {
                "live_mcp_endpoint_count": 1,
                "live_mcp_endpoints": [f"mcp.{domain}"],
                "rfc9728_present_count": 1,
                "missing_rfc9728_count": 0,
                "dns_aid_present": True,
                "apex_dnssec_enabled": True,
                "dns_aid_index_present": True,
                "dns_aid_catalog_separated": True,
                "dns_aid_agent_count": 1,
                "dns_aid_card_hash_verified_count": 1,
                "dns_aid_card_hash_mismatch_count": 0,
                "dane_tlsa_present": True,
                "dane_tlsa_count": 1,
                "ans_badge_present": True,
                "ans_badge_verified_count": 0 if include_spoof else 1,
                "spoofed_ans_badge_count": 1 if include_spoof else 0,
                "verified_first_party_agent_fqdns": [f"mcp.{domain}"] if include_spoof else [f"mcp.{domain}", agent_host, f"catalog.{domain}"],
                "chain_of_trust_surfaces": ["ard", "ucp", "spiffe_bundle", "spiffe_svid"],
            },
        },
        vector3={
            "permutations_tested": 6,
            "active_agent_endpoints": [
                {"domain": "mcp-brand-fake.com", "active_signals": [{"path": "/mcp"}]}
            ],
            "phishing_flagged": [
                {"domain": "brand-ai-login.com", "status": 403, "url": "https://brand-ai-login.com/", "matched_indicators": ["suspected phishing"]}
            ],
            "spoofed_ans_badge_hosts": [
                {
                    "domain": "agent-haven.dev",
                    "host": "travel.agent-haven.dev",
                    "receipt_host": "travel.agenthaven.dev",
                    "ans_name": "ans://v0.1.0.travel.agenthaven.dev",
                    "receipt_url": "https://transparency.example/v1/agents/uuid-9",
                    "receipt_status": "WARNING",
                    "dnssec_ad": True,
                }
            ]
            if not include_spoof
            else [],
            "flags": {
                "has_active_lookalike_agent_endpoint": True,
                "has_active_phishing_lookalike": True,
                "has_spoofed_ans_badge_lookalike": not include_spoof,
            },
        },
        telemetry={
            "rdap": {
                "enabled": True,
                "queried_count": 2,
                "resolved_count": 2,
                "nod_30d_count": 1,
                "nod_90d_count": 2,
                "nod_30d_domains": ["rogue-proxy.xyz"],
                "nod_90d_domains": ["rogue-proxy.xyz", "brand-ai-login.com"],
                "domains": {
                    "rogue-proxy.xyz": {
                        "domain": "rogue-proxy.xyz",
                        "ok": True,
                        "created_at": "2026-11-13T00:00:00Z",
                        "age_days": 11,
                        "is_nod_30d": True,
                        "is_nod_90d": True,
                        "registrar": "FreshReg <script>alert(1)</script> LLC",
                        "categories": ["v1_url_path_token_proxy"],
                    },
                    "brand-ai-login.com": {
                        "domain": "brand-ai-login.com",
                        "ok": True,
                        "created_at": "2026-09-25T00:00:00Z",
                        "age_days": 60,
                        "is_nod_30d": False,
                        "is_nod_90d": True,
                        "registrar": "Example Registrar Inc.",
                        "categories": ["v3_phishing_lookalike"],
                    },
                },
            }
        },
    )
    return rep.to_dict()


# ---------------------------------------------------------------------------
# 1. RDAP RFC 9083 Profiler Tests
# ---------------------------------------------------------------------------


def test_rdap_bootstrap_caching_nod_flags_and_fallback() -> None:
    clear_rdap_caches()
    now = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)

    bootstrap = {
        "services": [
            [["dev"], ["https://rdap.custom-dev.example/rdap/"]],
            [["com"], ["https://rdap.custom-com.example/v1/"]],
        ]
    }
    mock = _MockHttpClient(
        {
            "https://data.iana.org/rdap/dns.json": _json_resp("https://data.iana.org/rdap/dns.json", bootstrap),
            "https://rdap.custom-dev.example/rdap/domain/fresh-agent.dev": _json_resp(
                "https://rdap.custom-dev.example/rdap/domain/fresh-agent.dev",
                _sample_rdap_payload("2026-11-10T00:00:00Z", "Google Registry Test"),
            ),
            "https://rdap.custom-com.example/v1/domain/older-proxy.com": _json_resp(
                "https://rdap.custom-com.example/v1/domain/older-proxy.com",
                _sample_rdap_payload("2026-09-20T00:00:00Z", "Example Registrar Corp"),
            ),
            # Rate-limited / 429 graceful degradation
            "https://rdap.custom-com.example/v1/domain/throttled.com": HttpResponse(
                url="https://rdap.custom-com.example/v1/domain/throttled.com",
                final_url="https://rdap.custom-com.example/v1/domain/throttled.com",
                status=429,
                headers={},
                body_text="rate limited",
            ),
        }
    )

    p1 = lookup_rdap(mock, "sub.fresh-agent.dev", now=now)
    assert p1["ok"] is True
    assert p1["domain"] == "fresh-agent.dev"
    assert p1["age_days"] == 14
    assert p1["is_nod_30d"] is True
    assert p1["is_nod_90d"] is True
    assert p1["registrar"] == "Google Registry Test"
    assert "client transfer prohibited" in p1["status"]

    # Second call for same registrable domain must hit memory cache (0 new HTTP calls)
    calls_before = len(mock.calls)
    p1_cached = lookup_rdap(mock, "other.fresh-agent.dev", now=now)
    assert len(mock.calls) == calls_before
    assert p1_cached["age_days"] == 14

    # Different TLD uses already-cached IANA bootstrap (bootstrap fetched only once total)
    p2 = lookup_rdap(mock, "older-proxy.com", now=now)
    assert p2["ok"] is True
    assert p2["age_days"] == 65
    assert p2["is_nod_30d"] is False
    assert p2["is_nod_90d"] is True
    assert mock.calls.count("https://data.iana.org/rdap/dns.json") == 1

    # 429 degrades gracefully without crashing
    p_429 = lookup_rdap(mock, "throttled.com", now=now)
    assert p_429["ok"] is False
    assert p_429["error"] == "http_429"
    assert p_429["is_nod_30d"] is False

    # Fallback map when IANA bootstrap fails
    clear_rdap_caches()
    fb_mock = _MockHttpClient(
        {
            "https://data.iana.org/rdap/dns.json": HttpResponse(
                url="https://data.iana.org/rdap/dns.json",
                final_url="https://data.iana.org/rdap/dns.json",
                status=503,
                headers={},
                body_text="",
                error="http_503",
            ),
            "https://rdap.verisign.com/com/v1/domain/fallback-test.com": _json_resp(
                "https://rdap.verisign.com/com/v1/domain/fallback-test.com",
                _sample_rdap_payload("2020-01-01T00:00:00Z", "Legacy Registrar Inc"),
            ),
        }
    )
    p_fb = lookup_rdap(fb_mock, "fallback-test.com", now=now)
    assert p_fb["ok"] is True
    assert p_fb["is_nod_30d"] is False
    assert p_fb["is_nod_90d"] is False
    assert p_fb["registrar"] == "Legacy Registrar Inc"

    # Invalid/IP domains degrade gracefully without network calls
    p_ip = lookup_rdap(fb_mock, "192.0.2.10", now=now)
    assert p_ip["ok"] is False
    assert p_ip["error"] == "invalid_domain"


def test_rdap_enrich_report_profiles_v1_proxies_and_v3_lookalikes() -> None:
    clear_rdap_caches()
    now = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
    mock = _MockHttpClient(
        {
            "https://data.iana.org/rdap/dns.json": HttpResponse(
                url="https://data.iana.org/rdap/dns.json",
                final_url="https://data.iana.org/rdap/dns.json",
                status=503,
                headers={},
                body_text="",
            ),
            "https://rdap.verisign.com/com/v1/domain/phish-brand.com": _json_resp(
                "https://rdap.verisign.com/com/v1/domain/phish-brand.com",
                _sample_rdap_payload("2026-11-15T00:00:00Z", "FastReg"),
            ),
            "https://pubapi.registry.google/rdap/domain/agent-haven.dev": _json_resp(
                "https://pubapi.registry.google/rdap/domain/agent-haven.dev",
                _sample_rdap_payload("2026-11-20T00:00:00Z", "DevReg"),
            ),
            "https://rdap.centralnic.com/xyz/domain/proxy-relay.xyz": _json_resp(
                "https://rdap.centralnic.com/xyz/domain/proxy-relay.xyz",
                _sample_rdap_payload("2026-10-10T00:00:00Z", "XYZReg"),
            ),
        }
    )
    v1_data = {
        "mcp_registry": {
            "entries": [
                {
                    "name": "xyz.proxy-relay/mcp",
                    "classification": "unverified_3p_hosted_proxy",
                    "url_path_token_exposed": True,
                    "token_exposed_urls": ["https://api.proxy-relay.xyz/{token}"],
                    "remote_domains": ["proxy-relay.xyz"],
                    "remotes": [{"url": "https://api.proxy-relay.xyz/{token}"}],
                }
            ]
        }
    }
    v3_data = {
        "phishing_flagged": [{"domain": "phish-brand.com"}],
        "active_agent_endpoints": [],
        "spoofed_ans_badge_hosts": [{"domain": "agent-haven.dev", "host": "travel.agent-haven.dev"}],
    }
    summary = enrich_report_rdap(mock, v1_data, v3_data, max_domains=10, now=now)
    assert summary["queried_count"] == 3
    assert summary["resolved_count"] == 3
    assert summary["nod_30d_count"] == 2
    assert summary["nod_90d_count"] == 3
    assert "agent-haven.dev" in summary["nod_30d_domains"]
    assert "phish-brand.com" in summary["nod_30d_domains"]
    assert v3_data["phishing_flagged"][0]["rdap"]["is_nod_30d"] is True
    assert v3_data["spoofed_ans_badge_hosts"][0]["rdap"]["age_days"] == 4
    assert v1_data["mcp_registry"]["entries"][0]["remote_rdap"]["proxy-relay.xyz"]["age_days"] == 45


# ---------------------------------------------------------------------------
# 2. Protective DNS RPZ & JSON Domain Feed Tests
# ---------------------------------------------------------------------------


def test_rpz_and_domain_feed_self_dos_protection_and_spoofed_badge_blocking() -> None:
    rep = _make_rich_v03_report(domain="agenthaven.dev", include_spoof=False)
    feed = render_domain_feed(rep, policy_mode="block")
    by_fqdn = {e["fqdn"]: e for e in feed["entries"]}

    # Verified first-party MCP + DNS-AID hosts -> allow
    assert by_fqdn["mcp.agenthaven.dev"]["action"] == "allow"
    assert by_fqdn["travel.agenthaven.dev"]["action"] == "allow"
    assert by_fqdn["catalog.agenthaven.dev"]["action"] == "allow"

    # High-confidence threats -> block
    assert by_fqdn["travel.agent-haven.dev"]["action"] == "block"
    assert by_fqdn["travel.agent-haven.dev"]["category"] == "spoofed_ans_badge"
    assert by_fqdn["brand-ai-login.com"]["action"] == "block"
    assert by_fqdn["brand-ai-login.com"]["rdap_age_days"] == 60
    assert by_fqdn["mcp-brand-fake.com"]["action"] == "block"
    assert by_fqdn["relay.rogue-proxy.xyz"]["action"] == "block"
    assert by_fqdn["relay.rogue-proxy.xyz"]["rdap_age_days"] == 11

    # CRITICAL SELF-DOS CHECK: Shared multi-tenant platforms NEVER get NXDOMAIN block!
    assert is_shared_multitenant_platform("server.smithery.ai") is True
    assert is_shared_multitenant_platform("brand-community.vercel.app") is True
    assert is_shared_multitenant_platform("my-worker.workers.dev") is True
    assert is_shared_multitenant_platform("github.com") is True
    assert is_shared_multitenant_platform("api.cloudflare.com") is True

    assert by_fqdn["server.smithery.ai"]["action"] == "audit"
    assert "self-DoS" in by_fqdn["server.smithery.ai"]["reason"]
    assert by_fqdn["brand-community.vercel.app"]["action"] == "audit"

    # RPZ syntax checks (block mode)
    rpz_block = render_rpz(rep, zone_name="rpz.agentic-perimeter.local", policy_mode="block")
    assert "$TTL 300" in rpz_block
    assert "@   IN  SOA localhost. hostmaster.rpz.agentic-perimeter.local." in rpz_block
    assert "IN  NS  localhost." in rpz_block
    assert "mcp.agenthaven.dev  IN  CNAME  rpz-passthru." in rpz_block
    assert "travel.agenthaven.dev  IN  CNAME  rpz-passthru." in rpz_block
    assert "travel.agent-haven.dev  IN  CNAME  . ; BLOCK/NXDOMAIN [spoofed_ans_badge]" in rpz_block
    assert "relay.rogue-proxy.xyz  IN  CNAME  . ; BLOCK/NXDOMAIN [url_path_token_relay] [rdap_age=11d]" in rpz_block
    assert "server.smithery.ai  IN  CNAME  rpz-passthru. ; AUDIT [url_path_token_relay]" in rpz_block
    assert "server.smithery.ai  IN  CNAME  ." not in rpz_block
    assert "brand-community.vercel.app  IN  CNAME  ." not in rpz_block

    # RPZ audit mode: zero CNAME . entries
    rpz_audit = render_rpz(rep, policy_mode="audit")
    assert "  IN  CNAME  . " not in rpz_audit
    assert "travel.agent-haven.dev  IN  CNAME  rpz-passthru. ; AUDIT [spoofed_ans_badge]" in rpz_audit


def test_rpz_never_allowlists_spoofed_badge_host_on_direct_target_scan() -> None:
    # Direct audit of lookalike domain `agent-haven.dev` where its own agent host has spoofed `_ans-badge`
    rep = _make_rich_v03_report(domain="agent-haven.dev", include_spoof=True)
    feed = render_domain_feed(rep, policy_mode="block")
    by_fqdn = {e["fqdn"]: e for e in feed["entries"]}
    assert by_fqdn["travel.agent-haven.dev"]["action"] == "block"
    assert by_fqdn["travel.agent-haven.dev"]["category"] == "spoofed_ans_badge"


# ---------------------------------------------------------------------------
# 3. Longitudinal Cohort Trend Diff Engine Tests
# ---------------------------------------------------------------------------


def test_trend_engine_raw_batch_and_anonymized_study() -> None:
    rep_a_q4 = _make_rich_v03_report(domain="alpha.dev", include_spoof=True)
    rep_a_q4["score"]["control_posture_score"] = 45
    rep_a_q4["score"]["control_posture_grade"] = "D"
    rep_a_q4["score"]["threat_pressure_score"] = 60
    rep_a_q4["score"]["threat_pressure_level"] = "High"
    rep_a_q4["vector1"]["mcp_registry"]["official_count"] = 0
    rep_a_q4["vector1"]["flags"]["official_registry_vacuum"] = True

    rep_b_q4 = _make_rich_v03_report(domain="beta.dev", include_spoof=False)
    rep_b_q4["target"]["sector"] = "Fintech"
    rep_b_q4["score"]["control_posture_score"] = 80
    rep_b_q4["score"]["control_posture_grade"] = "B"
    rep_b_q4["score"]["threat_pressure_score"] = 20
    rep_b_q4["score"]["threat_pressure_level"] = "Low"

    batch_prev = {
        "tool_version": "0.2.0",
        "started_at": "2026-10-01T00:00:00Z",
        "finished_at": "2026-10-01T00:10:00Z",
        "reports": [rep_a_q4, rep_b_q4],
    }

    # Q1: alpha.dev improved (claimed official registry, fixed spoofed badge); beta.dev regressed; gamma.dev added
    rep_a_q1 = deepcopy(rep_a_q4)
    rep_a_q1["score"]["control_posture_score"] = 90
    rep_a_q1["score"]["control_posture_grade"] = "A"
    rep_a_q1["score"]["threat_pressure_score"] = 20
    rep_a_q1["score"]["threat_pressure_level"] = "Low"
    rep_a_q1["vector1"]["mcp_registry"]["official_count"] = 1
    rep_a_q1["vector1"]["flags"]["official_registry_vacuum"] = False
    rep_a_q1["vector2"]["dns_aid_linter"]["spoofed_ans_badge_hosts"] = []
    rep_a_q1["vector2"]["flags"]["spoofed_ans_badge_count"] = 0

    rep_b_q1 = deepcopy(rep_b_q4)
    rep_b_q1["score"]["control_posture_score"] = 60
    rep_b_q1["score"]["control_posture_grade"] = "C"
    rep_b_q1["score"]["threat_pressure_score"] = 50
    rep_b_q1["score"]["threat_pressure_level"] = "Moderate"

    rep_c_q1 = _make_rich_v03_report(domain="gamma.dev", include_spoof=False)
    rep_c_q1["target"]["sector"] = "Cloud"

    batch_curr = {
        "tool_version": "0.3.0",
        "started_at": "2027-01-15T00:00:00Z",
        "finished_at": "2027-01-15T00:12:00Z",
        "reports": [rep_a_q1, rep_b_q1, rep_c_q1],
    }

    trend = compute_trend(batch_prev, batch_curr, label_prev="2026-Q4", label_curr="2027-Q1")
    assert trend["input_format"] == "raw_batch"
    assert trend["cohort_overlap"]["matched_count"] == 2
    assert trend["cohort_overlap"]["added_targets"] == ["gamma.dev"]
    assert trend["cohort_overlap"]["removed_targets"] == []
    assert trend["adoption_and_exposure_deltas"]["official_mcp_registry_present"]["count_delta"] == 2
    assert trend["adoption_and_exposure_deltas"]["dane_tlsa_present"]["current_count"] == 3
    assert trend["target_movers"]["improved_count"] == 1
    assert trend["target_movers"]["improved"][0]["id"] == "alpha.dev"
    assert trend["target_movers"]["regressed_count"] == 1
    assert trend["target_movers"]["regressed"][0]["id"] == "beta.dev"
    assert "AI & Data" in trend["improved_sectors"]
    assert "Fintech" in trend["regressed_sectors"]

    md = render_trend_markdown(trend)
    assert "External Agentic Exposure Longitudinal Trend: 2026-Q4 -> 2027-Q1" in md
    assert "alpha.dev" in md
    assert "beta.dev" in md

    # Also verify direct compatibility with the real published Top-100 anonymized study JSON
    study_path = Path(__file__).resolve().parent.parent / "datasets" / "study_2027_anonymized.json"
    study_prev = json.loads(study_path.read_text(encoding="utf-8"))
    study_curr = deepcopy(study_prev)
    # Simulate 2 enterprises improving posture & adopting official registry + DNS-AID
    study_curr["anonymized_records"][0]["control_posture_applicable"] = True
    study_curr["anonymized_records"][0]["control_posture_score"] = 85
    study_curr["anonymized_records"][0]["control_posture_grade"] = "B"
    study_curr["anonymized_records"][0]["metrics"]["official_mcp_registry_count"] = 1
    study_curr["anonymized_records"][0]["metrics"]["dns_aid_present"] = True

    anon_trend = compute_trend(study_prev, study_curr, label_prev="2026-Q4", label_curr="2027-Q1")
    assert anon_trend["input_format"] == "anonymized_study"
    assert anon_trend["cohort_overlap"]["matched_count"] == 100
    assert anon_trend["adoption_and_exposure_deltas"]["dns_aid_present"]["count_delta"] == 1
    assert anon_trend["adoption_and_exposure_deltas"]["official_mcp_registry_present"]["count_delta"] == 1


# ---------------------------------------------------------------------------
# 4. CLI & HTML Report Integration Tests
# ---------------------------------------------------------------------------


def test_cli_v03_flags_rpz_feed_trend_and_html_wire_rendering(monkeypatch, tmp_path: Path) -> None:
    assert agentic_perimeter.__version__ == "0.3.1"
    rep_dict = _make_rich_v03_report(domain="agenthaven.dev", include_spoof=False)
    captured_kwargs: Dict[str, Any] = {}

    class _DummyReport:
        def to_dict(self) -> Dict[str, Any]:
            return rep_dict

    def _fake_audit(**kwargs: Any) -> _DummyReport:
        captured_kwargs.update(kwargs)
        return _DummyReport()

    monkeypatch.setattr(cli, "audit_domain", _fake_audit)

    rpz_path = tmp_path / "out.rpz"
    feed_path = tmp_path / "out_feed.json"
    html_path = tmp_path / "out.html"
    rc = cli.main(
        [
            "audit",
            "agenthaven.dev",
            "--rpz",
            str(rpz_path),
            "--domain-feed",
            str(feed_path),
            "--rpz-mode",
            "block",
            "--no-rdap",
            "--html",
            str(html_path),
            "--quiet",
        ]
    )
    assert rc == 0
    assert captured_kwargs.get("enable_rdap") is False
    assert "rpz-passthru." in rpz_path.read_text(encoding="utf-8")
    feed_json = json.loads(feed_path.read_text(encoding="utf-8"))
    assert feed_json["summary"]["block_count"] >= 3

    # Verify HTML report renders v0.3.0 wire-level DNS-AID/ANS panel + RDAP NOD badges safely with 0 CDN URLs
    html_out = html_path.read_text(encoding="utf-8")
    assert "Wire-Level DNS-AID (draft-02), DANE &amp; ANS v2 Validation" in html_out
    assert "bap=a2a alpn=a2a port=443 sig=present" in html_out
    assert "bap=[" not in html_out
    assert "Complementary Chain-of-Trust Surfaces" in html_out
    assert "Passive RFC 9083 RDAP Domain-Age &amp; Registrar Telemetry" in html_out
    assert "NOD &lt;30d (11d)" in html_out
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
    assert not re.search(r"<(script|link)[^>]+https?://", html_out, re.IGNORECASE)

    # Verify CLI `trend` subcommand end-to-end
    prev_p = tmp_path / "prev.json"
    curr_p = tmp_path / "curr.json"
    trend_json_p = tmp_path / "trend.json"
    trend_md_p = tmp_path / "trend.md"
    prev_p.write_text(json.dumps({"reports": [rep_dict]}), encoding="utf-8")
    curr_p.write_text(json.dumps({"reports": [rep_dict]}), encoding="utf-8")

    rc_t = cli.main(
        [
            "trend",
            str(prev_p),
            str(curr_p),
            "--label-prev",
            "2026-Q4",
            "--label-curr",
            "2027-Q1",
            "--json",
            str(trend_json_p),
            "--md",
            str(trend_md_p),
            "--quiet",
        ]
    )
    assert rc_t == 0
    assert json.loads(trend_json_p.read_text(encoding="utf-8"))["cohort_overlap"]["matched_count"] == 1
    assert "2026-Q4 -> 2027-Q1" in trend_md_p.read_text(encoding="utf-8")
