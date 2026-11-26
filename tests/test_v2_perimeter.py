"""Tests for Vector 2 hardened perimeter checks: DNS-AID, DNSSEC, RFC 9728, OAuth scopes, drift, and FP elimination."""

from __future__ import annotations

import json
import threading
from typing import Any, Dict

from agentic_perimeter.http_client import HttpResponse
from agentic_perimeter.models import BrandTarget
import agentic_perimeter.vector2_perimeter as v2mod


class FakeV2Client:
    def __init__(self, responses: Dict[str, HttpResponse]) -> None:
        self._responses = responses
        self._meta_lock = threading.Lock()
        self.certspotter_token = None
        self.github_token = None
        self.stats: Dict[str, Dict[str, int]] = {}

    def circuit_is_open(self, key: str) -> bool:
        return False

    def circuit_record_failure(self, *args: Any, **kwargs: Any) -> None:
        pass

    def circuit_trip(self, *args: Any, **kwargs: Any) -> None:
        pass

    def circuit_record_success(self, *args: Any, **kwargs: Any) -> None:
        pass

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        if url in self._responses:
            return self._responses[url]
        return HttpResponse(url=url, final_url=url, status=404, headers={}, body_text="")


def _resp(url: str, payload: Any, status: int = 200, headers: Dict[str, str] | None = None) -> HttpResponse:
    h = {"content-type": "application/json"}
    if headers:
        h.update(headers)
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return HttpResponse(url=url, final_url=url, status=status, headers=h, body_text=body)


def test_v2_missing_rfc9728_broad_scopes_dns_aid_and_no_agent_card_fp(monkeypatch) -> None:
    # Mock TLS cert inspection so tests are 100% offline
    monkeypatch.setattr(
        v2mod,
        "inspect_tls_cert",
        lambda host, timeout=4.5: {"hostname": host, "tls_ok": True, "verified": True, "sans": [host]},
    )

    responses = {
        # Apex DNSSEC AD=true + _agent SVCB DNS-AID record
        "https://dns.google/resolve?name=example.io&type=A&do=1": _resp(
            "https://dns.google/resolve?name=example.io&type=A&do=1",
            {"Status": 0, "AD": True, "Answer": [{"type": 1, "data": "93.184.216.34"}]},
        ),
        "https://dns.google/resolve?name=_agent.example.io&type=SVCB&do=1": _resp(
            "https://dns.google/resolve?name=_agent.example.io&type=SVCB&do=1",
            {"Status": 0, "AD": True, "Answer": [{"type": 64, "data": '1 mcp.example.io. alpn="h2"'}]},
        ),
        # CertSpotter returns legacy agent.example.io (must be dropped) + mcp.example.io
        "https://api.certspotter.com/v1/issuances?domain=example.io&include_subdomains=true&expand=dns_names": _resp(
            "https://api.certspotter.com/v1/issuances?domain=example.io&include_subdomains=true&expand=dns_names",
            [{"id": "999", "dns_names": ["agent.example.io", "mcp.example.io", "mcp-beta.example.io"]}],
        ),
        # Wildcard check NXDOMAIN
        "https://dns.google/resolve?name=agentic-perimeter-nx-9f8e7d.example.io&type=A": _resp(
            "https://dns.google/resolve?name=agentic-perimeter-nx-9f8e7d.example.io&type=A",
            {"Status": 3, "AD": False},
        ),
        # mcp.example.io resolves and has RFC 9728 with broad scopes
        "https://dns.google/resolve?name=mcp.example.io&type=A&do=1": _resp(
            "https://dns.google/resolve?name=mcp.example.io&type=A&do=1",
            {"Status": 0, "AD": True, "Answer": [{"type": 1, "data": "93.184.216.35"}]},
        ),
        "https://mcp.example.io/": _resp("https://mcp.example.io/", "", status=401),
        "https://mcp.example.io/mcp": _resp("https://mcp.example.io/mcp", "", status=401),
        "https://mcp.example.io/.well-known/oauth-protected-resource": _resp(
            "https://mcp.example.io/.well-known/oauth-protected-resource",
            {
                "resource": "https://mcp.example.io",
                "authorization_servers": ["https://auth.example.io"],
                "scopes_supported": ["read", "org:admin", "project:write", "delete:all"],
            },
        ),
        # mcp-beta.example.io resolves and serves /mcp 405 WITHOUT RFC 9728 -> must flag Missing RFC 9728!
        "https://dns.google/resolve?name=mcp-beta.example.io&type=A&do=1": _resp(
            "https://dns.google/resolve?name=mcp-beta.example.io&type=A&do=1",
            {"Status": 0, "AD": True, "Answer": [{"type": 1, "data": "93.184.216.36"}]},
        ),
        "https://mcp-beta.example.io/": _resp("https://mcp-beta.example.io/", "", status=405),
        "https://mcp-beta.example.io/mcp": _resp("https://mcp-beta.example.io/mcp", "", status=405),
        # Root /.well-known/agent.json (public docs card) + /.well-known/mcp.json pointing to sibling example.dev
        "https://example.io/.well-known/agent.json": _resp(
            "https://example.io/.well-known/agent.json",
            {"name": "Example Public Site Agent", "description": "Docs search"},
        ),
        "https://example.io/.well-known/mcp.json": _resp(
            "https://example.io/.well-known/mcp.json",
            {"name": "Example MCP", "endpoint": "https://mcp.example.dev/mcp"},
        ),
    }

    client = FakeV2Client(responses)
    target = BrandTarget(domain="example.io", brand="example")
    v2_data, findings, new_siblings = v2mod.probe_vector2(client, target, ["example.io"])

    # Legacy agent.example.io must NOT appear in CT subdomains
    assert "agent.example.io" not in (v2_data["ct_discovery"]["agent_subdomains"] or [])
    assert v2_data["flags"]["dns_aid_present"] is True
    assert v2_data["flags"]["apex_dnssec_enabled"] is True
    assert "example.dev" in new_siblings

    rule_ids = {f.rule_id for f in findings}
    assert "v2_broad_oauth_scope_declaration" in rule_ids
    assert "v2_cross_domain_perimeter_drift" in rule_ids
    # No unauthenticated_agent_card FP!
    assert all("unauthenticated" not in f.rule_id for f in findings)
    # mcp-beta.example.io has no prefix `mcp.` (starts with `mcp-`), so verify mcp.example.io had RFC 9728
    assert v2_data["flags"]["rfc9728_present_count"] == 1


def test_dns_aid_ignores_wildcard_spf_txt_and_wildcard_cname() -> None:
    from agentic_perimeter.dns_ct import probe_dns_aid

    responses = {
        "https://dns.google/resolve?name=corp.com&type=A&do=1": _resp(
            "x", {"Status": 0, "AD": True, "Answer": [{"type": 1, "data": "1.2.3.4"}]}
        ),
        "https://dns.google/resolve?name=_agent-nx-9f8e7d.corp.com&type=TXT": _resp(
            "x", {"Status": 0, "AD": False, "Answer": [{"type": 16, "data": "v=spf1 -all"}]}
        ),
        # Wildcard SPF TXT on _agent.corp.com -> must NOT count as DNS-AID
        "https://dns.google/resolve?name=_agent.corp.com&type=TXT&do=1": _resp(
            "x", {"Status": 0, "AD": True, "Answer": [{"type": 16, "data": "v=spf1 -all"}]}
        ),
        # Wildcard CNAME (type 5) returned for SVCB query -> must NOT count as DNS-AID
        "https://dns.google/resolve?name=_agent.corp.com&type=SVCB&do=1": _resp(
            "x", {"Status": 0, "AD": False, "Answer": [{"type": 5, "data": "elb.amazonaws.com."}]}
        ),
    }
    res = probe_dns_aid(FakeV2Client(responses), "corp.com")
    assert res["apex_dnssec_ad"] is True
    assert res["dns_aid_present"] is False
    assert res["records"] == []



def test_f11_v2_confirmed_mcp_signal_rejects_gateway_400_spa_html_and_sso_405() -> None:
    # F11a: Legacy gateway 400 error without MCP/JSON-RPC signal -> False
    r_gw_root = _resp("https://mcp.bank.com/", '{"errors": [{"error_code": "400-025"}]}', status=400)
    r_gw_mcp = _resp("https://mcp.bank.com/mcp", '{"errors": [{"error_code": "400-025"}]}', status=400)
    assert v2mod._has_confirmed_mcp_signal("mcp.bank.com", r_gw_root, r_gw_mcp, None, {}, None) is False

    # F11b: Multi-tenant React SPA returning 200 text/html on /mcp -> False
    r_spa_root = _resp("https://mcp.dash.net/", "<html><title>Dashboard</title></html>", status=200, headers={"content-type": "text/html; charset=UTF-8"})
    r_spa_mcp = _resp("https://mcp.dash.net/mcp", "<html><title>Dashboard</title></html>", status=200, headers={"content-type": "text/html; charset=UTF-8"})
    assert v2mod._has_confirmed_mcp_signal("mcp.dash.net", r_spa_root, r_spa_mcp, None, {}, None) is False

    # F11c: Multi-tenant SSO org returning 405 E0000022 -> False
    r_sso_root = HttpResponse(
        url="https://mcp.sso.com/",
        final_url="https://mcp.sso.com/app/UserHome?iss=https://mcp.sso.com",
        status=200,
        headers={"content-type": "text/html"},
        body_text="<title>Sign In</title>",
    )
    r_sso_mcp = _resp("https://mcp.sso.com/mcp", '{"errorCode":"E0000022","errorSummary":"Method not supported"}', status=405)
    assert v2mod._has_confirmed_mcp_signal("mcp.sso.com", r_sso_root, r_sso_mcp, None, {}, None) is False

    # True positives preserved: 401 non-HTML /mcp and 405 root
    r_tp_root = _resp("https://mcp.shop.com/", "", status=405)
    r_tp_mcp = _resp("https://mcp.shop.com/mcp", "", status=404)
    assert v2mod._has_confirmed_mcp_signal("mcp.shop.com", r_tp_root, r_tp_mcp, None, {}, None) is True

    r_tp2_root = _resp("https://mcp.api.com/", "", status=404)
    r_tp2_mcp = _resp("https://mcp.api.com/mcp", '{"error":"unauthorized"}', status=401)
    assert v2mod._has_confirmed_mcp_signal("mcp.api.com", r_tp2_root, r_tp2_mcp, None, {}, None) is True
