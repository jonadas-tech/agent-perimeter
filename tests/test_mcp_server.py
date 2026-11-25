"""Unit tests for the zero-dependency read-only MCP stdio server (`agentic-perimeter mcp`)."""

from __future__ import annotations

import io
import json

import agentic_perimeter
from agentic_perimeter import cli
from agentic_perimeter.mcp_server import handle_jsonrpc_message, serve_stdio
from agentic_perimeter.models import AuditReport, BrandTarget, ScoreSummary


def _dummy_report() -> AuditReport:
    return AuditReport(
        schema_version="2.0",
        tool_version=agentic_perimeter.__version__,
        scanned_at="2026-11-25T12:00:00Z",
        duration_seconds=0.42,
        target=BrandTarget(domain="example.com", brand="example"),
        verified_sibling_domains=["example.com"],
        score=ScoreSummary(
            scoring_model="2-axis-v1",
            control_posture_score=92,
            control_posture_grade="A",
            control_posture_label="Exemplary",
            control_posture_applicable=True,
            control_breakdown=[],
            threat_pressure_score=0,
            threat_pressure_level="None",
            threat_breakdown=[],
            action_posture="Well-Positioned",
            action_posture_summary="Strong first-party controls with low external pressure.",
            counts_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            counts_by_vector={"V1": 0, "V2": 0, "V3": 0},
            counts_by_axis={"first_party_control": 0, "external_threat": 0},
            ciso_takeaways=["Controls verified."],
            first_party_priorities=[],
            external_defense_priorities=[],
            top_priorities=[],
        ),
        findings=[],
        vector1={
            "mcp_registry": {
                "official_count": 1,
                "unverified_3p_hosted_proxy_count": 0,
                "url_path_token_exposed_count": 0,
                "official_servers": [{"name": "com.example/mcp"}],
                "unverified_3p_hosted_proxies": [],
            },
            "npm": {"official_count": 1, "unverified_count": 0, "free_email_unverified_count": 0},
            "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0},
        },
        vector2={"flags": {"live_mcp_endpoint_count": 1, "dns_aid_present": True}, "live_mcp_endpoints": []},
        vector3={"flags": {}, "active_agent_endpoints": [], "phishing_flagged": [], "spoofed_ans_badge_hosts": []},
        telemetry={"rdap": {"queried_count": 0, "resolved_count": 0}},
    )


def test_mcp_initialize_and_tools_list_annotations() -> None:
    init_resp = handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}},
        }
    )
    assert init_resp is not None
    assert init_resp["result"]["protocolVersion"] == "2025-03-26"
    assert init_resp["result"]["serverInfo"]["name"] == "agentic-perimeter"
    assert init_resp["result"]["serverInfo"]["version"] == agentic_perimeter.__version__

    # Notifications must return None
    assert handle_jsonrpc_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    tools_resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert tools_resp is not None
    tools = tools_resp["result"]["tools"]
    names = [t["name"] for t in tools]
    assert names == ["audit_domain", "lint_dns_aid"]
    for t in tools:
        assert t["annotations"]["readOnlyHint"] is True
        assert t["annotations"]["destructiveHint"] is False


def test_mcp_tools_call_audit_domain_and_stdio_framing(monkeypatch) -> None:
    import agentic_perimeter.mcp_server as mmod

    monkeypatch.setattr(mmod, "audit_domain", lambda **kwargs: _dummy_report())

    # Test NDJSON framing over stdio
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "audit_domain", "arguments": {"domain": "example.com", "include_rpz": True}},
        },
    ]
    stdin_buf = io.BytesIO(("\n".join(json.dumps(r) for r in requests) + "\n").encode("utf-8"))
    stdout_buf = io.BytesIO()

    rc = serve_stdio(stdin=stdin_buf, stdout=stdout_buf)
    assert rc == 0
    lines = [json.loads(line.decode("utf-8")) for line in stdout_buf.getvalue().splitlines() if line.strip()]
    assert len(lines) == 2
    assert lines[0]["id"] == 1 and lines[0]["result"] == {}
    assert lines[1]["id"] == 2
    assert lines[1]["result"]["isError"] is False
    structured = lines[1]["result"]["structuredContent"]
    assert structured["target"]["domain"] == "example.com"
    assert structured["score"]["control_posture_grade"] == "A"
    assert "SOA" in structured["rpz_policy"]

    # Also test Content-Length framing compatibility
    req_bytes = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode("utf-8")
    cl_stdin = io.BytesIO(f"Content-Length: {len(req_bytes)}\r\n\r\n".encode("ascii") + req_bytes)
    cl_stdout = io.BytesIO()
    assert serve_stdio(stdin=cl_stdin, stdout=cl_stdout) == 0
    raw_out = cl_stdout.getvalue()
    assert raw_out.startswith(b"Content-Length:")


def test_cli_mcp_subcommand_wiring(monkeypatch) -> None:
    import agentic_perimeter.mcp_server as mmod

    monkeypatch.setattr(mmod, "serve_stdio", lambda: 0)
    assert cli.main(["mcp"]) == 0
