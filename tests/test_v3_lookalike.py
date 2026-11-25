"""Tests for Vector 3 demoted silent lookalike sub-check (zero parking/HTTP 523 noise)."""

from __future__ import annotations

import json
import threading
from typing import Any, Dict

from agentic_perimeter.http_client import HttpResponse
from agentic_perimeter.models import BrandTarget
import agentic_perimeter.vector3_lookalike as v3mod


class FakeV3Client:
    def __init__(self, responses: Dict[str, HttpResponse]) -> None:
        self._responses = responses
        self._meta_lock = threading.Lock()

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        if url in self._responses:
            return self._responses[url]
        return HttpResponse(url=url, final_url=url, status=404, headers={}, body_text="")


def _resp(url: str, body: str, status: int = 200, headers: Dict[str, str] | None = None, final_url: str | None = None) -> HttpResponse:
    return HttpResponse(
        url=url,
        final_url=final_url or url,
        status=status,
        headers=headers or {"content-type": "text/html"},
        body_text=body,
    )


def _dns(a: list[str] | None = None, ns: list[str] | None = None) -> Dict[str, Any]:
    return {
        "Status": 0 if (a or ns) else 3,
        "AD": False,
        "Answer": [
            *([{"type": 1, "data": ip} for ip in (a or [])]),
            *([{"type": 2, "data": n} for n in (ns or [])]),
        ],
    }


def test_v3_suppresses_parking_523_markmonitor_and_alerts_only_active_mcp_and_phishing(monkeypatch) -> None:
    monkeypatch.setattr(
        v3mod,
        "inspect_tls_cert",
        lambda host, timeout=3.5: {"hostname": host, "tls_ok": True, "verified": True, "sans": [host], "issuer_cn": "Let's Encrypt"},
    )

    responses = {
        # 1. mcp-acme.com -> Cloudflare HTTP 523 squatter (MUST BE SUPPRESSED)
        "https://dns.google/resolve?name=mcp-acme.com&type=A": _resp("x", json.dumps(_dns(a=["104.21.1.1"]))),
        "https://mcp-acme.com/": _resp("https://mcp-acme.com/", "Origin Unreachable", status=523),
        # 2. acme-mcp.com -> GoDaddy parking IP 76.223.105.230 (MUST BE SUPPRESSED)
        "https://dns.google/resolve?name=acme-mcp.com&type=A": _resp("x", json.dumps(_dns(a=["76.223.105.230"]))),
        # 3. agent-acme.com -> MarkMonitor defensive reg (MUST BE SUPPRESSED)
        "https://dns.google/resolve?name=agent-acme.com&type=A": _resp("x", json.dumps(_dns(a=["1.2.3.4"]))),
        "https://agent-acme.com/": _resp("https://agent-acme.com/", "<title>Registered & Protected by MarkMonitor</title>", status=200),
        # 4. acme-agent.com -> Active third-party MCP endpoint serving /.well-known/mcp.json (MUST ALERT CRITICAL)
        "https://dns.google/resolve?name=acme-agent.com&type=A": _resp("x", json.dumps(_dns(a=["203.0.113.10"]))),
        "https://acme-agent.com/": _resp("https://acme-agent.com/", "<title>Acme Agent Hub</title>", status=200),
        "https://acme-agent.com/.well-known/mcp.json": _resp(
            "https://acme-agent.com/.well-known/mcp.json",
            json.dumps({"name": "Fake Acme MCP", "endpoint": "https://acme-agent.com/mcp"}),
            status=200,
            headers={"content-type": "application/json"},
        ),
        # 5. ai-acme.com -> Cloudflare Suspected Phishing interstitial (MUST ALERT HIGH)
        "https://dns.google/resolve?name=ai-acme.com&type=A": _resp("x", json.dumps(_dns(a=["104.21.2.2"]))),
        "https://ai-acme.com/": _resp("https://ai-acme.com/", "<title>Suspected Phishing | Cloudflare</title>", status=403),
        # 6. acme-ai.com -> Generic unrelated blog returning HTML 200 on /mcp (MUST BE SUPPRESSED)
        "https://dns.google/resolve?name=acme-ai.com&type=A": _resp("x", json.dumps(_dns(a=["198.51.100.5"]))),
        "https://acme-ai.com/": _resp("https://acme-ai.com/", "<title>Acme AI Blog</title>", status=200),
        "https://acme-ai.com/mcp": _resp("https://acme-ai.com/mcp", "<html><body>Login next=%2Fmcp</body></html>", status=200),
    }

    client = FakeV3Client(responses)
    v3_data, findings = v3mod.probe_vector3(client, BrandTarget(domain="acme.com", brand="acme"), ["acme.com"])

    assert v3_data["suppressed_noise"]["http_523_or_unreachable"] == 1
    assert v3_data["suppressed_noise"]["parked_or_for_sale"] == 1
    assert v3_data["suppressed_noise"]["defensive_brand_owned"] == 1
    assert v3_data["suppressed_noise"]["generic_non_agent_site"] == 1

    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule.keys()) == {"v3_active_lookalike_agent_endpoint", "v3_active_phishing_lookalike"}
    assert by_rule["v3_active_lookalike_agent_endpoint"].severity == "critical"
    assert by_rule["v3_active_phishing_lookalike"].severity == "high"


def test_f12_v3_ignores_http200_suspected_phishing_body_prose(monkeypatch) -> None:
    monkeypatch.setattr(
        v3mod,
        "inspect_tls_cert",
        lambda host, timeout=3.5: {"hostname": host, "tls_ok": True, "verified": True, "sans": [host], "issuer_cn": "Let's Encrypt"},
    )
    # HTTP 200 generic page whose body mentions "Report suspected phishing to IT Security" MUST NOT trigger phishing interstitial
    responses = {
        "https://dns.google/resolve?name=acme-agent.com&type=A": _resp("x", json.dumps(_dns(a=["198.51.100.7"]))),
        "https://acme-agent.com/": _resp(
            "https://acme-agent.com/",
            "<html><title>Employee Portal — Sign in</title><body><p>Report suspected phishing to the IT Security team.</p></body></html>",
            status=200,
        ),
    }
    client = FakeV3Client(responses)
    v3_data, findings = v3mod.probe_vector3(client, BrandTarget(domain="acme.com", brand="acme"), ["acme.com"])
    assert v3_data["phishing_flagged"] == []
    assert findings == []
