"""Offline deterministic tests for wire-level DNS-AID (draft-02), ANS v2 (_ans-badge),
DANE TLSA, card-tampering verification, Chain-of-Trust surface detection, and V2/V3/scoring integration.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
from typing import Any, Dict

from agentic_perimeter.dns_aid_linter import (
    check_ans_badge,
    host_from_ans_name,
    lint_dns_aid,
    parse_dns_aid_index_txt,
    parse_svcb_rdata,
    parse_tlsa_rdata,
    verify_card_digest,
)
from agentic_perimeter.http_client import HttpResponse
from agentic_perimeter.models import BrandTarget
from agentic_perimeter.scoring import rescore_report_dict, score_audit
from agentic_perimeter.taxonomy import ALL_FINDING_DEFINITIONS, PROTOCOL_FINDING_DEFINITIONS
import agentic_perimeter.vector2_perimeter as v2mod
import agentic_perimeter.vector3_lookalike as v3mod


class FakeWireClient:
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


def _doh(name: str, rtype: str, answers: list[tuple[int, str]], ad: bool = True, dnssec: bool = True) -> tuple[str, HttpResponse]:
    do_part = "&do=1" if dnssec else ""
    url = f"https://dns.google/resolve?name={name}&type={rtype}{do_part}"
    body = {
        "Status": 0 if answers else 3,
        "AD": ad,
        "Answer": [{"type": t, "data": d} for t, d in answers],
    }
    return url, _resp(url, body)


def _b64u_sha256(text: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii").rstrip("=")


def _make_jws(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.sigplaceholder"


def _encode_dns_name(fqdn: str) -> bytes:
    if fqdn == ".":
        return b"\x00"
    out = bytearray()
    for lbl in fqdn.rstrip(".").split("."):
        b = lbl.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def test_parse_svcb_presentation_private_keys_octal_escapes_and_jws() -> None:
    jws = _make_jws(
        {"alg": "ES256", "kid": "dnsaid-2026-09", "typ": "JWT"},
        {"fqdn": "travel.example.dev", "target": "travel.example.dev", "alpn": "a2a", "port": 443},
    )
    rdata = (
        f"1 travel.example.dev. mandatory=alpn,port alpn=a2a port=443 "
        f"key65400=https://travel.example.dev/.well-known/agent-card.json "
        f"key65401=sWJzLIPAuM_xhwpvjtKYy3xJ6VI75YPZo6gxYFJ2xr0 "
        f"key65402=a2a key65405={jws} key65409=agent-card.json"
    )
    parsed = parse_svcb_rdata(rdata)
    assert parsed is not None
    assert parsed["format"] == "presentation"
    assert parsed["priority"] == 1
    assert parsed["mode"] == "service"
    assert parsed["target"] == "travel.example.dev"
    assert parsed["mandatory"] == ["alpn", "port"]
    assert parsed["alpn"] == ["a2a"]
    assert parsed["port"] == 443
    assert parsed["cap"] == "https://travel.example.dev/.well-known/agent-card.json"
    assert parsed["cap_sha256"] == "sWJzLIPAuM_xhwpvjtKYy3xJ6VI75YPZo6gxYFJ2xr0"
    assert parsed["bap"] == ["a2a"]
    assert parsed["sig"] == jws
    assert parsed["sig_claims"]["fqdn"] == "travel.example.dev"
    assert parsed["sig_claims"]["alg"] == "ES256"
    assert parsed["private_keys"]["key65409"] == "agent-card.json"

    # AliasMode (priority 0)
    alias_rec = parse_svcb_rdata("0 catalog.example.dev.")
    assert alias_rec is not None
    assert alias_rec["mode"] == "alias"
    assert alias_rec["target"] == "catalog.example.dev"

    # Self-target `.` with RFC 1035 decimal octal escapes (`\044` = ',')
    self_rec = parse_svcb_rdata(r'1 . alpn="h2\044h3" port=443 key65402="mcp\044a2a"')
    assert self_rec is not None
    assert self_rec["target"] == "."
    assert self_rec["alpn"] == ["h2", "h3"]
    assert self_rec["bap"] == ["mcp", "a2a"]


def test_parse_svcb_rfc3597_wire_hex() -> None:
    def tlv(key: int, val: bytes) -> bytes:
        return key.to_bytes(2, "big") + len(val).to_bytes(2, "big") + val

    wire = bytearray()
    wire.extend((1).to_bytes(2, "big"))  # priority 1
    wire.extend(_encode_dns_name("agent.example.dev."))
    # mandatory = alpn (1), port (3)
    wire.extend(tlv(0, (1).to_bytes(2, "big") + (3).to_bytes(2, "big")))
    # alpn = ["h2", "mcp"]
    wire.extend(tlv(1, b"\x02h2\x03mcp"))
    # port = 443
    wire.extend(tlv(3, (443).to_bytes(2, "big")))
    # ipv4hint = 203.0.113.10
    wire.extend(tlv(4, socket.inet_pton(socket.AF_INET, "203.0.113.10")))
    # ipv6hint = 2001:db8::1
    wire.extend(tlv(6, socket.inet_pton(socket.AF_INET6, "2001:db8::1")))
    # private-use draft keys
    wire.extend(tlv(65400, b"https://agent.example.dev/.well-known/agent-card.json"))
    wire.extend(tlv(65401, b"digest-b64url-value"))
    wire.extend(tlv(65402, b"mcp"))

    rdata = f"\\# {len(wire)} {wire.hex()}"
    parsed = parse_svcb_rdata(rdata)
    assert parsed is not None
    assert parsed["format"] == "rfc3597_wire"
    assert parsed["priority"] == 1
    assert parsed["target"] == "agent.example.dev"
    assert parsed["mandatory"] == ["alpn", "port"]
    assert parsed["alpn"] == ["h2", "mcp"]
    assert parsed["port"] == 443
    assert parsed["ipv4hint"] == ["203.0.113.10"]
    assert parsed["ipv6hint"] == ["2001:db8::1"]
    assert parsed["cap"] == "https://agent.example.dev/.well-known/agent-card.json"
    assert parsed["cap_sha256"] == "digest-b64url-value"
    assert parsed["bap"] == ["mcp"]


def test_parse_tlsa_google_cloudflare_and_rfc3597() -> None:
    digest = "a" * 64
    # Google presentation
    g = parse_tlsa_rdata(f"3 0 1 {digest}")
    assert g is not None
    assert g["usage"] == 3 and g["usage_name"] == "DANE-EE"
    assert g["selector"] == 0 and g["matching_type"] == 1
    assert g["data_hex"] == digest and g["valid_syntax"] is True

    # Cloudflare parenthesized uppercase presentation
    cf = parse_tlsa_rdata(f"3 1 1 ( {digest.upper()} )")
    assert cf is not None
    assert cf["usage"] == 3 and cf["selector"] == 1 and cf["selector_name"] == "SPKI"
    assert cf["data_hex"] == digest and cf["valid_syntax"] is True

    # RFC 3597 unknown-RR wire hex
    raw = bytes([3, 1, 1]) + bytes.fromhex(digest)
    w = parse_tlsa_rdata(f"\\# {len(raw)} {raw.hex()}")
    assert w is not None
    assert w["usage"] == 3 and w["selector"] == 1 and w["valid_syntax"] is True

    # Invalid length for SHA-256 (matching_type 1 requires 64 hex chars)
    bad = parse_tlsa_rdata("3 0 1 abcd")
    assert bad is not None
    assert bad["valid_syntax"] is False


def test_card_digest_verification_and_tampering_detection() -> None:
    card_body = json.dumps({"name": "Demo Agent", "version": "1.0"})
    b64u = _b64u_sha256(card_body)
    hex_digest = hashlib.sha256(card_body.encode("utf-8")).hexdigest()
    card_url = "https://travel.example.dev/.well-known/agent-card.json"

    client = FakeWireClient({card_url: _resp(card_url, card_body)})

    # Unpadded base64url exact match
    v_ok = verify_card_digest(client, card_url, b64u)
    assert v_ok["status"] == "verified"
    assert v_ok["computed_sha256"] == b64u

    # Padded base64url exact match
    v_pad = verify_card_digest(client, card_url, b64u + "=")
    assert v_pad["status"] == "verified"

    # Hex digest match
    v_hex = verify_card_digest(client, card_url, f"sha256:{hex_digest.upper()}")
    assert v_hex["status"] == "verified"

    # Tampered card mismatch
    v_bad = verify_card_digest(client, card_url, "wrong_digest_0000000000000000000000000000000")
    assert v_bad["status"] == "mismatch"

    # Missing URL / HTTP 404
    v_404 = verify_card_digest(client, "https://travel.example.dev/missing.json", b64u)
    assert v_404["status"] == "fetch_error"


def test_ans_badge_host_binding_verified_and_spoofed_copied_badge() -> None:
    assert host_from_ans_name("ans://v0.1.0.travel.example.dev") == "travel.example.dev"
    assert host_from_ans_name("ans://v1.2.3.auditor.skybound-demo.com/") == "auditor.skybound-demo.com"

    receipt_url = "https://transparency.example.net/v1/agents/uuid-1234"
    receipt = {
        "status": "ACTIVE",
        "schemaVersion": "V1",
        "payload": {
            "producer": {
                "event": {
                    "ansId": "uuid-1234",
                    "ansName": "ans://v0.1.0.travel.example.dev",
                    "agent": {"host": "travel.example.dev", "name": "Demo Travel"},
                }
            }
        },
    }
    txt_val = f'"v=ans-badge1; version=v0.1.0; url={receipt_url}"'

    responses: Dict[str, HttpResponse] = {receipt_url: _resp(receipt_url, receipt)}
    u1, r1 = _doh("_ans-badge.travel.example.dev", "TXT", [(16, txt_val)], ad=True)
    u2, r2 = _doh("_ans-badge.travel.example-lookalike.dev", "TXT", [(16, txt_val)], ad=True)
    responses[u1] = r1
    responses[u2] = r2
    client = FakeWireClient(responses)

    legit = check_ans_badge(client, "travel.example.dev")
    assert legit["present"] is True
    assert legit["host_binding_status"] == "verified"
    assert legit["spoofed"] is False
    assert legit["receipt_host"] == "travel.example.dev"

    spoofed = check_ans_badge(client, "travel.example-lookalike.dev")
    assert spoofed["present"] is True
    assert spoofed["host_binding_status"] == "host_mismatch"
    assert spoofed["spoofed"] is True
    assert spoofed["receipt_host"] == "travel.example.dev"
    assert spoofed["ans_name"] == "ans://v0.1.0.travel.example.dev"


def test_v2_wire_integration_findings_chain_of_trust_and_wildcard_filtering(monkeypatch) -> None:
    monkeypatch.setattr(
        v2mod,
        "inspect_tls_cert",
        lambda host, timeout=4.5: {"hostname": host, "tls_ok": True, "verified": True, "sans": [host]},
    )

    good_card = json.dumps({"name": "Good Agent"})
    good_hash = _b64u_sha256(good_card)
    bad_card = json.dumps({"name": "Tampered Agent"})
    receipt_good_url = "https://log.example.net/v1/agents/good"
    receipt_other_url = "https://log.example.net/v1/agents/other"

    responses: Dict[str, HttpResponse] = {}
    for u, r in [
        _doh("demo.dev", "A", [(1, "203.0.113.1")], ad=True),
        _doh("_index._agents.demo.dev", "SVCB", [(64, "1 catalog.demo.dev. alpn=h2 port=443")], ad=True),
        _doh("_index._agents.demo.dev", "TXT", [(16, '"agents=good:mcp,bad:a2a"')], ad=True),
        # good.demo.dev: valid card digest, DNSSEC DANE TLSA, valid ANS badge
        _doh(
            "good.demo.dev",
            "SVCB",
            [(64, f"1 . alpn=h2 port=443 key65400=https://good.demo.dev/.well-known/agent-card.json key65401={good_hash} key65402=mcp")],
            ad=True,
        ),
        _doh("_443._tcp.good.demo.dev", "TLSA", [(52, f"3 1 1 ( {'B' * 64} )")], ad=True),
        _doh("_ans-badge.good.demo.dev", "TXT", [(16, f"v=ans-badge1; version=v1.0.0; url={receipt_good_url}")], ad=True),
        # bad.demo.dev: tampered card digest, unsigned DANE TLSA (AD=False), spoofed ANS badge
        _doh(
            "bad.demo.dev",
            "SVCB",
            [(64, "1 bad.demo.dev. alpn=a2a port=443 key65400=https://bad.demo.dev/.well-known/agent-card.json key65401=stale_digest_value key65402=a2a")],
            ad=True,
        ),
        _doh("_443._tcp.bad.demo.dev", "TLSA", [(52, f"3 0 1 {'c' * 64}")], ad=False),
        _doh("_ans-badge.bad.demo.dev", "TXT", [(16, f"v=ans-badge1; version=v1.0.0; url={receipt_other_url}")], ad=True),
        # _agent-keys TXT on demo.dev
        _doh("_agent-keys.demo.dev", "TXT", [(16, '"v=agentkey1; k=ed25519; p=AAAA"')], ad=True),
    ]:
        responses[u] = r

    responses["https://good.demo.dev/.well-known/agent-card.json"] = _resp(
        "https://good.demo.dev/.well-known/agent-card.json", good_card
    )
    responses["https://bad.demo.dev/.well-known/agent-card.json"] = _resp(
        "https://bad.demo.dev/.well-known/agent-card.json", bad_card
    )
    responses[receipt_good_url] = _resp(
        receipt_good_url,
        {"status": "ACTIVE", "payload": {"producer": {"event": {"ansName": "ans://v1.0.0.good.demo.dev", "agent": {"host": "good.demo.dev"}}}}},
    )
    responses[receipt_other_url] = _resp(
        receipt_other_url,
        {"status": "ACTIVE", "payload": {"producer": {"event": {"ansName": "ans://v1.0.0.other.example.com", "agent": {"host": "other.example.com"}}}}},
    )
    # Chain-of-trust surfaces
    responses["https://demo.dev/.well-known/ard.json"] = _resp(
        "https://demo.dev/.well-known/ard.json",
        {"specVersion": "1.0", "host": {"identifier": "https://demo.dev"}, "entries": [{"identifier": "urn:air:demo.dev:good"}]},
    )
    responses["https://good.demo.dev/.well-known/ucp"] = _resp(
        "https://good.demo.dev/.well-known/ucp",
        {
            "ucp": {
                "version": "2026-08-25",
                "services": {"dev.ucp.shopping": []},
                "capabilities": {"dev.ucp.common.payment.ap2_mandate": [{"config": {"dev.demo.mandate_issuers": ["https://issuer.demo.dev"]}}]},
            },
            "keys": [{"kty": "EC"}],
        },
    )
    responses["https://good.demo.dev/.well-known/spiffe-bundle.json"] = _resp(
        "https://good.demo.dev/.well-known/spiffe-bundle.json", {"keys": [{"kty": "EC", "kid": "k1"}]}
    )
    responses["https://good.demo.dev/.well-known/spiffe-svid.json"] = _resp(
        "https://good.demo.dev/.well-known/spiffe-svid.json", {"spiffe_id": "spiffe://demo.dev/agent/good", "instance_id": "inst1"}
    )

    client = FakeWireClient(responses)
    v2_data, findings, _ = v2mod.probe_vector2(client, BrandTarget(domain="demo.dev", brand="demo"), ["demo.dev"])

    flags = v2_data["flags"]
    assert flags["dns_aid_present"] is True
    assert flags["dns_aid_index_present"] is True
    assert flags["dns_aid_catalog_separated"] is True
    assert flags["dns_aid_agent_count"] == 2
    assert flags["dns_aid_card_hash_verified_count"] == 1
    assert flags["dns_aid_card_hash_mismatch_count"] == 1
    assert flags["dane_tlsa_present"] is True
    assert flags["dane_tlsa_count"] == 2
    assert flags["ans_badge_verified_count"] == 1
    assert flags["spoofed_ans_badge_count"] == 1
    assert "good.demo.dev" in flags["verified_first_party_agent_fqdns"]
    assert "catalog.demo.dev" in flags["verified_first_party_agent_fqdns"]
    assert "bad.demo.dev" not in flags["verified_first_party_agent_fqdns"]

    cot = v2_data["chain_of_trust"]
    assert set(cot["surfaces_detected"]) == {"ard", "ucp", "spiffe_bundle", "spiffe_svid", "agent_keys_txt"}
    assert cot["ucp"][0]["mandate_issuers"] == ["https://issuer.demo.dev"]

    rule_ids = {f.rule_id for f in findings}
    assert "v2_dns_aid_card_hash_mismatch" in rule_ids
    assert "v2_ans_badge_host_mismatch" in rule_ids
    assert "v2_dane_tlsa_without_dnssec" in rule_ids


def test_v3_spoofed_ans_badge_on_delegated_lookalike_and_scoring_integration(monkeypatch) -> None:
    monkeypatch.setattr(
        v3mod,
        "inspect_tls_cert",
        lambda host, timeout=3.5: {"hostname": host, "tls_ok": True, "verified": True, "sans": [host]},
    )

    receipt_url = "https://transparency.example.net/v1/agents/copied-uuid"
    responses: Dict[str, HttpResponse] = {
        receipt_url: _resp(
            receipt_url,
            {
                "status": "WARNING",
                "payload": {
                    "producer": {
                        "event": {
                            "ansName": "ans://v0.1.0.travel.agentdemo.dev",
                            "agent": {"host": "travel.agentdemo.dev"},
                        }
                    }
                },
            },
        )
    }
    # Delegated hyphenated lookalike `agent-demo.dev` (NS only on apex, agent host via _index._agents)
    for u, r in [
        _doh("agent-demo.dev", "NS", [(2, "ns1.cloudflare.com.")], ad=False, dnssec=False),
        _doh("_index._agents.agent-demo.dev", "TXT", [(16, '"agents=travel:a2a"')], ad=True),
        _doh(
            "_ans-badge.travel.agent-demo.dev",
            "TXT",
            [(16, f'"v=ans-badge1; version=v0.1.0; url={receipt_url}"')],
            ad=True,
        ),
    ]:
        responses[u] = r

    client = FakeWireClient(responses)
    target = BrandTarget(domain="agentdemo.dev", brand="agentdemo")
    v3_data, findings = v3mod.probe_vector3(client, target, ["agentdemo.dev"])

    assert v3_data["flags"]["has_spoofed_ans_badge_lookalike"] is True
    assert len(v3_data["spoofed_ans_badge_hosts"]) == 1
    hit = v3_data["spoofed_ans_badge_hosts"][0]
    assert hit["domain"] == "agent-demo.dev"
    assert hit["host"] == "travel.agent-demo.dev"
    assert hit["receipt_host"] == "travel.agentdemo.dev"

    assert len(findings) == 1
    assert findings[0].rule_id == "v3_spoofed_ans_badge_lookalike"
    assert findings[0].severity == "critical"
    assert findings[0].axis == "external_threat"

    # Verify scoring & rescoring handle protocol findings cleanly
    v1_empty = {
        "mcp_registry": {"official_count": 0, "unverified_3p_hosted_proxy_count": 0, "url_path_token_exposed_count": 0, "entries": []},
        "npm": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"has_any_mcp_footprint": False},
    }
    v2_min = {
        "dns_aid": {"apex_dnssec_ad": True, "dns_aid_present": True},
        "flags": {"apex_dnssec_enabled": True, "dns_aid_present": True, "dns_aid_index_present": True, "dns_aid_agent_count": 1},
    }
    sc = score_audit(target, findings, v1_empty, v2_min, v3_data)
    assert sc.threat_pressure_score == 50
    assert sc.threat_pressure_level == "High"
    assert any(t["id"] == "T7" and t["points"] == 50 for t in sc.threat_breakdown)

    # Neutral labels check across all protocol finding definitions
    for rid, defn in PROTOCOL_FINDING_DEFINITIONS.items():
        assert rid in ALL_FINDING_DEFINITIONS
        assert "malicious" not in str(defn["label"]).lower()

    # rescore_report_dict round-trip
    rescored = rescore_report_dict(
        {
            "target": {"domain": "agentdemo.dev", "brand": "agentdemo"},
            "vector1": v1_empty,
            "vector2": v2_min,
            "vector3": v3_data,
            "findings": [f.to_dict() for f in findings],
        }
    )
    assert rescored["score"]["threat_pressure_score"] == 50
    assert rescored["findings"][0]["rule_id"] == "v3_spoofed_ans_badge_lookalike"


def test_linter_ignores_wildcard_spf_txt_and_wildcard_cname() -> None:
    assert parse_dns_aid_index_txt(['"v=spf1 -all"', "v=DMARC1; p=reject"]) == []
    responses: Dict[str, HttpResponse] = {}
    for u, r in [
        _doh("wc.example.com", "A", [(1, "198.51.100.1")], ad=False),
        _doh("_agent-nx-9f8e7d.wc.example.com", "TXT", [(16, '"v=spf1 -all"')], ad=False, dnssec=False),
        _doh("_index._agents.wc.example.com", "TXT", [(16, '"v=spf1 -all"')], ad=False),
        _doh("_index._agents.wc.example.com", "SVCB", [(5, "wildcard.elb.example.net.")], ad=False),
    ]:
        responses[u] = r
    res = lint_dns_aid(FakeWireClient(responses), "wc.example.com")
    assert res["index_found"] is False
    assert res["indexed_agents"] == []
    assert res["agent_records"] == []
    assert res["spoofed_ans_badge_hosts"] == []


def test_pure_dns_aid_scoring_grade_a_and_c6_integrity_priorities() -> None:
    v1_empty = {
        "mcp_registry": {"official_count": 0, "unverified_3p_hosted_proxy_count": 0, "url_path_token_exposed_count": 0, "entries": []},
        "npm": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "pypi": {"official_count": 0, "unverified_count": 0, "free_email_unverified_count": 0, "packages": []},
        "flags": {"has_any_mcp_footprint": False},
    }
    v3_empty = {
        "permutations_tested": 6,
        "active_agent_endpoints": [],
        "phishing_flagged": [],
        "spoofed_ans_badge_hosts": [],
        "flags": {
            "has_active_lookalike_agent_endpoint": False,
            "has_active_phishing_lookalike": False,
            "has_spoofed_ans_badge_lookalike": False,
        },
    }

    # 1. Pure DNS-AID/ANS deployment with 0 MCP footprint & verified wire integrity -> 100/100 Grade A (C1 = N/A)
    v2_clean = {
        "dns_aid": {"apex_dnssec_ad": True, "dns_aid_present": True},
        "flags": {
            "apex_dnssec_enabled": True,
            "dns_aid_present": True,
            "dns_aid_index_present": True,
            "dns_aid_agent_count": 4,
            "dns_aid_card_hash_verified_count": 4,
            "dns_aid_card_hash_mismatch_count": 0,
            "dane_tlsa_count": 5,
            "ans_badge_verified_count": 4,
            "spoofed_ans_badge_count": 0,
        },
    }
    sc_clean = score_audit(BrandTarget(domain="pure-dnsaid.dev", brand="purednsaid"), [], v1_empty, v2_clean, v3_empty)
    c_by_id = {c["id"]: c for c in sc_clean.control_breakdown}
    assert c_by_id["C1"]["status"] == "na"
    assert c_by_id["C6"]["status"] == "pass"
    assert sc_clean.control_posture_score == 100
    assert sc_clean.control_posture_grade == "A"
    assert sc_clean.action_posture == "Well-Positioned"

    # 2. Pure DNS-AID host with spoofed ANS badge & card hash mismatch -> C6 partial + explicit first_party_priorities
    v2_bad = {
        "dns_aid": {"apex_dnssec_ad": True, "dns_aid_present": True},
        "flags": {
            "apex_dnssec_enabled": True,
            "dns_aid_present": True,
            "dns_aid_index_present": True,
            "dns_aid_agent_count": 1,
            "dns_aid_card_hash_verified_count": 0,
            "dns_aid_card_hash_mismatch_count": 1,
            "dane_tlsa_count": 1,
            "ans_badge_verified_count": 0,
            "spoofed_ans_badge_count": 1,
        },
    }
    sc_bad = score_audit(BrandTarget(domain="bad-dnsaid.dev", brand="baddnsaid"), [], v1_empty, v2_bad, v3_empty)
    assert sc_bad.control_posture_score == 67
    assert sc_bad.control_posture_grade == "C"
    assert any("[DNS-AID Integrity]" in p for p in sc_bad.first_party_priorities)
    assert any("[ANS Badge Binding]" in p for p in sc_bad.first_party_priorities)
