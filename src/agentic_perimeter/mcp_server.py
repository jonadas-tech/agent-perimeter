"""Zero-dependency, read-only MCP stdio server (`agentic-perimeter mcp`).

Implements the Model Context Protocol (MCP) JSON-RPC 2.0 transport over stdio
using strictly the Python 3.11+ standard library. All exposed tools are 100%
passive and read-only (`readOnlyHint=True`, `destructiveHint=False`).
"""

from __future__ import annotations

import contextlib
import json
import sys
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from . import __version__
from .dns_aid_linter import doh_query, lint_dns_aid
from .dns_policy import render_rpz
from .http_client import PoliteHttpClient
from .scanner import audit_domain, normalize_target

SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
DEFAULT_PROTOCOL_VERSION = "2025-03-26"

TOOLS_SPEC: List[Dict[str, Any]] = [
    {
        "name": "audit_domain",
        "description": (
            "Run a 100% passive external attack surface audit on an organization's domain: "
            "cross-registry MCP supply-chain provenance (Official MCP Registry, npm, PyPI, GitHub), "
            "unverified 3rd-party hosted proxies, wire-level IETF DNS-AID (draft-02) / DNSSEC / DANE TLSA / "
            "ANS v2 _ans-badge host binding, RFC 9728 OAuth Protected Resource metadata, passive RDAP domain age, "
            "and high-signal lookalike endpoints, mapped to OWASP Agentic Top 10 (2026) and OWASP MCP Top 10."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Primary target domain to audit passively (e.g. 'cloudflare.com', 'skybound-travel.com').",
                },
                "brand": {
                    "type": "string",
                    "description": "Optional explicit brand token override if different from domain label.",
                },
                "inspect_packages": {
                    "type": "boolean",
                    "description": "Passively inspect up to 10 unverified npm/PyPI tarballs strictly in memory (<=5 MB, zero execution).",
                    "default": False,
                },
                "include_lookalike": {
                    "type": "boolean",
                    "description": "Include silent high-signal V3 lookalike infrastructure check.",
                    "default": True,
                },
                "include_rpz": {
                    "type": "boolean",
                    "description": "Include open-standard BIND/RFC Protective DNS RPZ zone output.",
                    "default": False,
                },
                "rpz_mode": {
                    "type": "string",
                    "enum": ["audit", "block"],
                    "description": "RPZ policy mode when include_rpz is true ('audit' or 'block').",
                    "default": "audit",
                },
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
        "annotations": {
            "title": "Passive External Agentic Perimeter Audit",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
    {
        "name": "lint_dns_aid",
        "description": (
            "Fast, targeted passive wire-level linter for IETF DNS-AID (draft-mozleywilliams-dnsop-dnsaid-02), "
            "apex DNSSEC (AD=true), DANE TLSA (_443._tcp), OWASP ANS v2 (_ans-badge strict host-binding anti-spoofing), "
            "and agentic Chain-of-Trust .well-known discovery surfaces on a domain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to lint for DNS-AID, DANE TLSA, DNSSEC, and ANS v2 records (e.g. 'skybound-travel.com').",
                },
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
        "annotations": {
            "title": "Passive Wire-Level DNS-AID & ANS v2 Linter",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    },
]


def _compact_audit_payload(report_dict: Dict[str, Any], include_rpz: bool = False, rpz_mode: str = "audit") -> Dict[str, Any]:
    v1 = report_dict.get("vector1") or {}
    v1_reg = v1.get("mcp_registry") or {}
    v1_npm = v1.get("npm") or {}
    v1_pypi = v1.get("pypi") or {}
    v2 = report_dict.get("vector2") or {}
    v3 = report_dict.get("vector3") or {}
    tel = report_dict.get("telemetry") or {}

    out: Dict[str, Any] = {
        "schema_version": report_dict.get("schema_version"),
        "tool_version": report_dict.get("tool_version"),
        "scanned_at": report_dict.get("scanned_at"),
        "duration_seconds": round(float(report_dict.get("duration_seconds") or 0.0), 2),
        "target": report_dict.get("target"),
        "verified_sibling_domains": report_dict.get("verified_sibling_domains") or [],
        "score": report_dict.get("score"),
        "findings": report_dict.get("findings") or [],
        "vector1_summary": {
            "mcp_registry": {
                "official_count": v1_reg.get("official_count", 0),
                "unverified_3p_hosted_proxy_count": v1_reg.get("unverified_3p_hosted_proxy_count", 0),
                "url_path_token_exposed_count": v1_reg.get("url_path_token_exposed_count", 0),
                "official_servers": v1_reg.get("official_servers") or [],
                "unverified_3p_hosted_proxies": (v1_reg.get("unverified_3p_hosted_proxies") or [])[:15],
            },
            "npm": {
                "official_count": v1_npm.get("official_count", 0),
                "unverified_count": v1_npm.get("unverified_count", 0),
                "free_email_unverified_count": v1_npm.get("free_email_unverified_count", 0),
                "security_holding_count": len(v1_npm.get("security_holding_packages") or []),
            },
            "pypi": {
                "official_count": v1_pypi.get("official_count", 0),
                "unverified_count": v1_pypi.get("unverified_count", 0),
                "free_email_unverified_count": v1_pypi.get("free_email_unverified_count", 0),
            },
        },
        "vector2_summary": {
            "flags": v2.get("flags") or {},
            "live_mcp_endpoints": v2.get("live_mcp_endpoints") or [],
            "dns_aid_wire": v2.get("dns_aid_wire") or {},
        },
        "vector3_summary": {
            "flags": v3.get("flags") or {},
            "active_agent_endpoints": v3.get("active_agent_endpoints") or [],
            "phishing_flagged": v3.get("phishing_flagged") or [],
            "spoofed_ans_badge_hosts": v3.get("spoofed_ans_badge_hosts") or [],
        },
        "rdap_summary": tel.get("rdap") or {},
    }
    if "static_package_audit" in v1:
        out["vector1_summary"]["static_package_audit"] = v1["static_package_audit"]
    if include_rpz:
        mode = rpz_mode if rpz_mode in ("audit", "block") else "audit"
        out["rpz_policy"] = render_rpz(report_dict, policy_mode=mode)
    return out


def _execute_tool(name: str, arguments: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    if name == "audit_domain":
        raw_domain = str(arguments.get("domain") or "").strip()
        if not raw_domain:
            raise ValueError("Missing required string parameter 'domain'.")
        brand = arguments.get("brand")
        inspect_pkgs = bool(arguments.get("inspect_packages", False))
        include_lookalike = bool(arguments.get("include_lookalike", True))
        include_rpz = bool(arguments.get("include_rpz", False))
        rpz_mode = str(arguments.get("rpz_mode") or "audit")

        with contextlib.redirect_stdout(sys.stderr):
            rep = audit_domain(
                domain=raw_domain,
                brand=str(brand).strip() if brand else None,
                include_lookalike=include_lookalike,
                inspect_packages=inspect_pkgs,
            )
            payload = _compact_audit_payload(rep.to_dict(), include_rpz=include_rpz, rpz_mode=rpz_mode)
        return payload, False

    if name == "lint_dns_aid":
        raw_domain = str(arguments.get("domain") or "").strip()
        if not raw_domain:
            raise ValueError("Missing required string parameter 'domain'.")
        target = normalize_target(raw_domain)
        with contextlib.redirect_stdout(sys.stderr):
            client = PoliteHttpClient(enable_github_search=False)
            soa_res = doh_query(client, target.domain, "SOA", dnssec=True)
            apex_dnssec = bool(soa_res.get("ad"))
            wire = lint_dns_aid(client, target.domain, verified_domains=[target.domain])
        payload = {
            "domain": target.domain,
            "tool_version": __version__,
            "apex_dnssec_ad": apex_dnssec,
            "dns_aid_wire": wire,
        }
        return payload, False

    raise KeyError(f"Unknown tool: {name!r}")


def handle_jsonrpc_message(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC 2.0 message and return a response dict (or None for notifications)."""
    if not isinstance(msg, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request"},
        }

    method = msg.get("method")
    msg_id = msg.get("id")
    is_notification = "id" not in msg

    if is_notification:
        return None

    if method == "initialize":
        params = msg.get("params") or {}
        req_ver = str(params.get("protocolVersion") or "")
        negotiated = req_ver if req_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": "agentic-perimeter",
                    "version": __version__,
                },
                "instructions": (
                    "Passive, read-only external attack surface scanner for MCP supply-chain provenance, "
                    "IETF DNS-AID / DNSSEC / ANS v2, and RFC 9728 OAuth metadata."
                ),
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method in ("resources/list",):
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}

    if method in ("prompts/list",):
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS_SPEC}}

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object."},
            }
        try:
            payload, is_err = _execute_tool(tool_name, arguments)
            text_json = json.dumps(payload, indent=2, ensure_ascii=False)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": text_json}],
                    "structuredContent": payload,
                    "isError": is_err,
                },
            }
        except KeyError as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": str(exc)},
            }
        except Exception as exc:
            err_payload = {"error": f"{type(exc).__name__}: {exc}"}
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(err_payload)}],
                    "isError": True,
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method!r}"},
    }


def _read_message(stream: BinaryIO) -> Tuple[Optional[Dict[str, Any]], str]:
    """Read one JSON-RPC message supporting both newline-delimited JSON (MCP stdio) and Content-Length framing."""
    while True:
        line = stream.readline()
        if not line:
            return None, "ndjson"
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hdr = stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = stream.read(length)
            if not body:
                return None, "content-length"
            return json.loads(body.decode("utf-8")), "content-length"
        return json.loads(stripped.decode("utf-8")), "ndjson"


def _write_message(stream: BinaryIO, payload: Dict[str, Any], framing: str = "ndjson") -> None:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if framing == "content-length":
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        stream.write(header + encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


def serve_stdio(stdin: Optional[BinaryIO] = None, stdout: Optional[BinaryIO] = None) -> int:
    in_stream = stdin or sys.stdin.buffer
    out_stream = stdout or sys.stdout.buffer
    while True:
        try:
            msg, framing = _read_message(in_stream)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            _write_message(out_stream, err_resp, "ndjson")
            continue
        if msg is None:
            break
        resp = handle_jsonrpc_message(msg)
        if resp is not None:
            _write_message(out_stream, resp, framing)
    return 0


def main() -> int:
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
