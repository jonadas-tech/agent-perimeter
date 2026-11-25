"""Wire-level passive linter for IETF DNS-AID (draft-mozleywilliams-dnsop-dnsaid-02),
ANS v2 (_ans-badge rev 02), DANE TLSA, and complementary agentic chain-of-trust surfaces.

100% passive, read-only, Python standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import urllib.parse

from .dns_ct import doh_query, host_matches_any, registrable_domain
from .http_client import HttpResponse, PoliteHttpClient

# Standard RFC 9460 SvcParamKey registry names
_SVCB_STANDARD_KEY_NAMES: Dict[int, str] = {
    0: "mandatory",
    1: "alpn",
    2: "no-default-alpn",
    3: "port",
    4: "ipv4hint",
    5: "ech",
    6: "ipv6hint",
    7: "dohpath",
}

# TLSA (RFC 6698) human-readable field names
_TLSA_USAGE_NAMES: Dict[int, str] = {
    0: "PKIX-TA",
    1: "PKIX-EE",
    2: "DANE-TA",
    3: "DANE-EE",
}
_TLSA_SELECTOR_NAMES: Dict[int, str] = {
    0: "Cert",
    1: "SPKI",
}
_TLSA_MATCHING_NAMES: Dict[int, str] = {
    0: "Full",
    1: "SHA-256",
    2: "SHA-512",
}

_DNS_OCTAL_RE = re.compile(r"\\(\d{3})")
_ANS_VERSION_PREFIX_RE = re.compile(r"^v\d+(?:\.\d+)*\.", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_AGENT_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Text / Wire Helpers
# ---------------------------------------------------------------------------
def _unescape_dns_presentation(value: str) -> str:
    """Decode RFC 1035 / RFC 9460 presentation escapes (\\DDD decimal octets and \\x)."""
    if "\\" not in value:
        return value
    out = bytearray()
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and i + 1 < n:
            if i + 3 < n and value[i + 1 : i + 4].isdigit():
                octet = int(value[i + 1 : i + 4])
                if 0 <= octet <= 255:
                    out.append(octet)
                    i += 4
                    continue
            out.extend(value[i + 1].encode("utf-8"))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", errors="replace")


def clean_txt_value(raw: str) -> str:
    """Normalize a DoH TXT RR string across Google (unquoted) and Cloudflare (quoted segments)."""
    s = (raw or "").strip()
    if not s:
        return ""
    # Handle Cloudflare multi-segment quoted strings like: '"part1" "part2"'
    if s.startswith('"') and s.endswith('"'):
        segments: List[str] = []
        i = 0
        n = len(s)
        while i < n:
            while i < n and s[i].isspace():
                i += 1
            if i >= n:
                break
            if s[i] == '"':
                i += 1
                buf: List[str] = []
                while i < n:
                    if s[i] == "\\" and i + 1 < n:
                        buf.append(s[i : i + 2])
                        i += 2
                        continue
                    if s[i] == '"':
                        i += 1
                        break
                    buf.append(s[i])
                    i += 1
                segments.append(_unescape_dns_presentation("".join(buf)))
            else:
                j = i
                while j < n and not s[j].isspace():
                    j += 1
                segments.append(_unescape_dns_presentation(s[i:j]))
                i = j
        if segments:
            # Join key=value segments cleanly with space if multiple segments look like k=v pairs
            if len(segments) > 1 and all("=" in seg for seg in segments):
                return " ".join(segments)
            return "".join(segments)
    return _unescape_dns_presentation(s)


def _decode_b64url_json(segment: str) -> Optional[Dict[str, Any]]:
    """Decode a base64url-encoded JSON object (e.g., JWT/JWS header or payload) passively."""
    s = (segment or "").strip()
    if not s:
        return None
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    try:
        raw = base64.urlsafe_b64decode(s + pad)
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _decode_jws_claims(token: str) -> Optional[Dict[str, Any]]:
    """Passively inspect unverified JWS/JWT header & payload claims in key65405."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return None
    header = _decode_b64url_json(parts[0])
    payload = _decode_b64url_json(parts[1])
    if not payload:
        return None
    claims: Dict[str, Any] = {}
    if header:
        if "alg" in header:
            claims["alg"] = header.get("alg")
        if "kid" in header:
            claims["kid"] = header.get("kid")
        if "typ" in header:
            claims["typ"] = header.get("typ")
    for k in ("fqdn", "target", "alpn", "port", "svcb", "iat", "exp"):
        if k in payload:
            claims[k] = payload[k]
    return claims or None


def _parse_json_body(resp: HttpResponse) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    if resp.status != 200:
        return False, None, f"http_{resp.status}"
    body = (resp.body_text or "").lstrip()
    if not body:
        return False, None, "empty_body"
    if body.lower().startswith(("<!doctype", "<html", "<head", "<body")):
        return False, None, "soft_404_html"
    try:
        parsed = json.loads(resp.body_text)
        if isinstance(parsed, dict):
            return True, parsed, "valid_json_object"
        return False, None, "json_not_object"
    except Exception:
        return False, None, "invalid_json"


# ---------------------------------------------------------------------------
# 1. RFC 9460 SVCB & Private-Use Draft Keys Parser (Presentation + RFC 3597)
# ---------------------------------------------------------------------------
def _tokenize_svcb_presentation(rdata: str) -> List[str]:
    """Split an SVCB presentation string into tokens while preserving quoted substrings."""
    tokens: List[str] = []
    cur: List[str] = []
    in_quotes = False
    i = 0
    n = len(rdata)
    while i < n:
        ch = rdata[i]
        if ch == "\\" and i + 1 < n:
            cur.append(ch)
            cur.append(rdata[i + 1])
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            cur.append(ch)
            i += 1
            continue
        if ch.isspace() and not in_quotes:
            if cur:
                tokens.append("".join(cur))
                cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        tokens.append("".join(cur))
    return tokens


def _strip_optional_quotes(val: str) -> str:
    s = val.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return _unescape_dns_presentation(s)


def _decode_dns_wire_name(buf: bytes, offset: int) -> Tuple[str, int]:
    """Decode an uncompressed RFC 1035 wire-format domain name starting at offset."""
    labels: List[str] = []
    n = len(buf)
    while offset < n:
        llen = buf[offset]
        offset += 1
        if llen == 0:
            break
        if llen & 0xC0:
            raise ValueError("compressed_name_not_allowed_in_svcb")
        if offset + llen > n:
            raise ValueError("truncated_dns_name")
        labels.append(buf[offset : offset + llen].decode("ascii", errors="replace").lower())
        offset += llen
    if not labels:
        return ".", offset
    return ".".join(labels), offset


def _parse_svcb_wire_hex(rdata: str) -> Optional[Dict[str, Any]]:
    """Parse RFC 3597 unknown-RR wire hex (`\\# <len> <hex bytes>`) for SVCB (type 64)."""
    s = rdata.strip()
    if not s.startswith(r"\#"):
        return None
    rest = s[2:].strip()
    parts = rest.split()
    if len(parts) < 2 or not parts[0].isdigit():
        return None
    declared_len = int(parts[0])
    hex_blob = "".join(parts[1:])
    if not _HEX_RE.match(hex_blob) or len(hex_blob) % 2 != 0:
        return None
    raw = bytes.fromhex(hex_blob)
    if len(raw) < 3 or (declared_len and len(raw) != declared_len):
        return None

    priority = int.from_bytes(raw[0:2], "big")
    try:
        target, pos = _decode_dns_wire_name(raw, 2)
    except ValueError:
        return None

    params: Dict[str, str] = {}
    alpn: List[str] = []
    port: Optional[int] = None
    mandatory: List[str] = []
    ipv4hint: List[str] = []
    ipv6hint: List[str] = []
    ech: Optional[str] = None
    private_keys: Dict[str, str] = {}

    n = len(raw)
    while pos + 4 <= n:
        key_num = int.from_bytes(raw[pos : pos + 2], "big")
        val_len = int.from_bytes(raw[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + val_len > n:
            break
        vbytes = raw[pos : pos + val_len]
        pos += val_len

        key_name = _SVCB_STANDARD_KEY_NAMES.get(key_num, f"key{key_num}")
        if key_num == 0:  # mandatory
            keys: List[str] = []
            for kpos in range(0, len(vbytes) - 1, 2):
                mk = int.from_bytes(vbytes[kpos : kpos + 2], "big")
                keys.append(_SVCB_STANDARD_KEY_NAMES.get(mk, f"key{mk}"))
            mandatory = keys
            params["mandatory"] = ",".join(keys)
        elif key_num == 1:  # alpn
            apos = 0
            protos: List[str] = []
            while apos < len(vbytes):
                alen = vbytes[apos]
                apos += 1
                if apos + alen > len(vbytes):
                    break
                protos.append(vbytes[apos : apos + alen].decode("utf-8", errors="replace"))
                apos += alen
            alpn = protos
            params["alpn"] = ",".join(protos)
        elif key_num == 2:  # no-default-alpn
            params["no-default-alpn"] = "true"
        elif key_num == 3 and len(vbytes) == 2:  # port
            port = int.from_bytes(vbytes, "big")
            params["port"] = str(port)
        elif key_num == 4 and len(vbytes) % 4 == 0:  # ipv4hint
            ips = [socket.inet_ntop(socket.AF_INET, vbytes[i : i + 4]) for i in range(0, len(vbytes), 4)]
            ipv4hint = ips
            params["ipv4hint"] = ",".join(ips)
        elif key_num == 5:  # ech
            ech = base64.b64encode(vbytes).decode("ascii")
            params["ech"] = ech
        elif key_num == 6 and len(vbytes) % 16 == 0:  # ipv6hint
            ips6 = [socket.inet_ntop(socket.AF_INET6, vbytes[i : i + 16]) for i in range(0, len(vbytes), 16)]
            ipv6hint = ips6
            params["ipv6hint"] = ",".join(ips6)
        else:
            try:
                decoded = vbytes.decode("utf-8")
            except UnicodeDecodeError:
                decoded = base64.urlsafe_b64encode(vbytes).decode("ascii").rstrip("=")
            params[key_name] = decoded
            if 65280 <= key_num <= 65534:
                private_keys[key_name] = decoded

    return _finalize_svcb_dict(
        raw=rdata,
        fmt="rfc3597_wire",
        priority=priority,
        target=target,
        params=params,
        alpn=alpn,
        port=port,
        mandatory=mandatory,
        ipv4hint=ipv4hint,
        ipv6hint=ipv6hint,
        ech=ech,
        private_keys=private_keys,
    )


def _finalize_svcb_dict(
    raw: str,
    fmt: str,
    priority: int,
    target: str,
    params: Dict[str, str],
    alpn: List[str],
    port: Optional[int],
    mandatory: List[str],
    ipv4hint: List[str],
    ipv6hint: List[str],
    ech: Optional[str],
    private_keys: Dict[str, str],
) -> Dict[str, Any]:
    cap = params.get("key65400") or params.get("cap")
    cap_sha256 = params.get("key65401") or params.get("cap-sha256")
    bap_raw = params.get("key65402") or params.get("bap") or ""
    bap = [p.strip().lower() for p in bap_raw.split(",") if p.strip()]
    sig = params.get("key65405") or params.get("sig")
    sig_claims = _decode_jws_claims(sig) if sig else None

    norm_target = target.strip().lower()
    if norm_target != ".":
        norm_target = norm_target.rstrip(".")

    return {
        "raw": raw,
        "format": fmt,
        "priority": priority,
        "mode": "alias" if priority == 0 else "service",
        "target": norm_target or ".",
        "params": params,
        "alpn": alpn,
        "port": port,
        "mandatory": mandatory,
        "ipv4hint": ipv4hint,
        "ipv6hint": ipv6hint,
        "ech": ech,
        "cap": cap,
        "cap_sha256": cap_sha256,
        "bap": bap,
        "sig": sig,
        "sig_claims": sig_claims,
        "private_keys": private_keys,
    }


def parse_svcb_rdata(rdata: str) -> Optional[Dict[str, Any]]:
    """Parse an RFC 9460 SVCB RDATA string (presentation format or RFC 3597 wire hex)."""
    s = (rdata or "").strip()
    if not s:
        return None
    if s.startswith(r"\#"):
        return _parse_svcb_wire_hex(s)

    tokens = _tokenize_svcb_presentation(s)
    if len(tokens) < 2 or not tokens[0].isdigit():
        return None

    priority = int(tokens[0])
    target = tokens[1].strip()
    params: Dict[str, str] = {}
    alpn: List[str] = []
    port: Optional[int] = None
    mandatory: List[str] = []
    ipv4hint: List[str] = []
    ipv6hint: List[str] = []
    ech: Optional[str] = None
    private_keys: Dict[str, str] = {}

    for tok in tokens[2:]:
        if "=" in tok:
            k_raw, v_raw = tok.split("=", 1)
            k = k_raw.strip().lower()
            v = _strip_optional_quotes(v_raw)
        else:
            k = tok.strip().lower()
            v = "true"

        if not k:
            continue
        params[k] = v

        if k == "alpn":
            alpn = [p.strip() for p in v.split(",") if p.strip()]
        elif k == "port" and v.isdigit():
            port = int(v)
        elif k == "mandatory":
            mandatory = [p.strip().lower() for p in v.split(",") if p.strip()]
        elif k == "ipv4hint":
            ipv4hint = [p.strip() for p in v.split(",") if p.strip()]
        elif k == "ipv6hint":
            ipv6hint = [p.strip() for p in v.split(",") if p.strip()]
        elif k == "ech":
            ech = v
        elif k.startswith("key") and k[3:].isdigit():
            knum = int(k[3:])
            if 65280 <= knum <= 65534:
                private_keys[k] = v

    return _finalize_svcb_dict(
        raw=rdata,
        fmt="presentation",
        priority=priority,
        target=target,
        params=params,
        alpn=alpn,
        port=port,
        mandatory=mandatory,
        ipv4hint=ipv4hint,
        ipv6hint=ipv6hint,
        ech=ech,
        private_keys=private_keys,
    )


# ---------------------------------------------------------------------------
# 2. DNS-AID Index TXT Parsing
# ---------------------------------------------------------------------------
def parse_dns_aid_index_txt(raw_records: Sequence[str]) -> List[Dict[str, str]]:
    """Parse `_index._agents.<domain>` TXT entries into normalized `{name, protocol}` pairs.

    Supports live wire formats:
      - `agents=travel:a2a,car-rental:a2a,hotel:a2a`
      - `"agents=auditor:mcp,authority:mcp,buyer:mcp,seller:a2a"`
      - `entries=travel:a2a`
      - `_travel._a2a._agents.example.com` or `travel:mcp`
    """
    found: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    for raw in raw_records:
        cleaned = clean_txt_value(raw).strip()
        if not cleaned:
            continue
        low = cleaned.lower()
        if low.startswith(("v=spf1", "v=dmarc1", "v=dkim1")):
            continue

        # Support semicolon/space separated clauses containing agents=... or entries=...
        chunks: List[str] = []
        if "agents=" in low or "entries=" in low:
            for part in re.split(r"[;\s]+", cleaned):
                if "=" in part:
                    pk, pv = part.split("=", 1)
                    if pk.strip().lower() in ("agents", "entries"):
                        chunks.extend(pv.split(","))
        else:
            chunks.extend(re.split(r"[,;\s]+", cleaned))

        for item in chunks:
            tok = item.strip().strip("\"'")
            if not tok:
                continue
            name = ""
            proto = ""
            if ":" in tok and "://" not in tok:
                n_part, p_part = tok.split(":", 1)
                name = n_part.strip().lstrip("_").lower()
                proto = p_part.strip().lstrip("_").lower()
            elif "._agents." in tok.lower():
                # e.g. _travel._a2a._agents.example.com or travel._mcp._agents.example.com
                prefix = tok.lower().split("._agents.", 1)[0]
                labels = [lb.lstrip("_") for lb in prefix.split(".") if lb]
                if len(labels) >= 2:
                    name, proto = labels[0], labels[1]
            if name and proto and _AGENT_LABEL_RE.match(name) and _AGENT_LABEL_RE.match(proto):
                key = (name, proto)
                if key not in seen:
                    seen.add(key)
                    found.append({"name": name, "protocol": proto})

    return found


# ---------------------------------------------------------------------------
# 3. Passive Card-Tampering Check (`key65400` vs `key65401`)
# ---------------------------------------------------------------------------
def verify_card_digest(
    client: PoliteHttpClient,
    cap_url: Optional[str],
    expected_digest: Optional[str],
) -> Dict[str, Any]:
    """Passively fetch the `cap` URL (key65400) in memory and compare SHA-256 against `key65401`."""
    if not cap_url:
        return {
            "status": "no_cap_url",
            "cap_url": None,
            "expected_sha256": expected_digest,
            "computed_sha256": None,
            "http_status": 0,
            "error": None,
        }
    parsed = urllib.parse.urlparse(cap_url)
    if parsed.scheme.lower() not in ("https", "http") or not parsed.netloc:
        return {
            "status": "fetch_error",
            "cap_url": cap_url,
            "expected_sha256": expected_digest,
            "computed_sha256": None,
            "http_status": 0,
            "error": "invalid_cap_url_scheme",
        }
    if not expected_digest:
        return {
            "status": "no_digest",
            "cap_url": cap_url,
            "expected_sha256": None,
            "computed_sha256": None,
            "http_status": 0,
            "error": None,
        }

    resp = client.get(
        cap_url,
        timeout=5.5,
        max_bytes=262144,
        retries=0,
        accept="application/json, */*;q=0.5",
    )
    if resp.status != 200 or not resp.body_text:
        return {
            "status": "fetch_error",
            "cap_url": cap_url,
            "expected_sha256": expected_digest,
            "computed_sha256": None,
            "http_status": resp.status,
            "error": resp.error or f"http_{resp.status}",
        }

    digest_bytes = hashlib.sha256(resp.body_text.encode("utf-8")).digest()
    computed_b64u = base64.urlsafe_b64encode(digest_bytes).decode("ascii").rstrip("=")
    computed_hex = digest_bytes.hex()

    exp_clean = expected_digest.strip()
    for prefix in ("sha256:", "sha-256:", "sha256="):
        if exp_clean.lower().startswith(prefix):
            exp_clean = exp_clean[len(prefix) :].strip()
            break

    if len(exp_clean) == 64 and _HEX_RE.match(exp_clean):
        matched = exp_clean.lower() == computed_hex
        computed_display = computed_hex
    else:
        matched = exp_clean.rstrip("=") == computed_b64u
        computed_display = computed_b64u

    return {
        "status": "verified" if matched else "mismatch",
        "cap_url": resp.final_url or cap_url,
        "expected_sha256": exp_clean,
        "computed_sha256": computed_display,
        "http_status": resp.status,
        "error": None,
    }


# ---------------------------------------------------------------------------
# 4. DANE TLSA & DNSSEC Parser / Probe
# ---------------------------------------------------------------------------
def parse_tlsa_rdata(rdata: str) -> Optional[Dict[str, Any]]:
    """Parse a TLSA (type 52) record across Google, Cloudflare parenthesized, and RFC 3597 hex formats."""
    s = (rdata or "").strip()
    if not s:
        return None

    usage: int
    selector: int
    matching_type: int
    data_hex: str

    if s.startswith(r"\#"):
        parts = s[2:].strip().split()
        if len(parts) < 2 or not parts[0].isdigit():
            return None
        hex_blob = "".join(parts[1:])
        if not _HEX_RE.match(hex_blob) or len(hex_blob) % 2 != 0:
            return None
        raw = bytes.fromhex(hex_blob)
        if len(raw) < 4:
            return None
        usage, selector, matching_type = raw[0], raw[1], raw[2]
        data_hex = raw[3:].hex()
    else:
        # Cloudflare returns: '3 0 1 ( 619CCEEAC0E70F2F... )'
        normalized = s.replace("(", " ").replace(")", " ")
        parts = normalized.split()
        if len(parts) < 4:
            return None
        if not (parts[0].isdigit() and parts[1].isdigit() and parts[2].isdigit()):
            return None
        usage = int(parts[0])
        selector = int(parts[1])
        matching_type = int(parts[2])
        data_hex = "".join(parts[3:]).lower()

    valid_fields = usage in _TLSA_USAGE_NAMES and selector in _TLSA_SELECTOR_NAMES and matching_type in _TLSA_MATCHING_NAMES
    valid_hex = bool(data_hex and _HEX_RE.match(data_hex) and len(data_hex) % 2 == 0)
    if matching_type == 1:
        valid_len = len(data_hex) == 64
    elif matching_type == 2:
        valid_len = len(data_hex) == 128
    else:
        valid_len = len(data_hex) >= 2

    return {
        "raw": rdata,
        "usage": usage,
        "usage_name": _TLSA_USAGE_NAMES.get(usage, f"unknown({usage})"),
        "selector": selector,
        "selector_name": _TLSA_SELECTOR_NAMES.get(selector, f"unknown({selector})"),
        "matching_type": matching_type,
        "matching_name": _TLSA_MATCHING_NAMES.get(matching_type, f"unknown({matching_type})"),
        "data_hex": data_hex,
        "valid_syntax": bool(valid_fields and valid_hex and valid_len),
    }


def probe_dane_tlsa(client: PoliteHttpClient, host: str, port: int = 443) -> Dict[str, Any]:
    """Passively query `_<port>._tcp.<host>` TLSA (type 52) with DNSSEC AD validation."""
    clean_host = host.strip().lower().rstrip(".")
    qname = f"_{port}._tcp.{clean_host}"
    res = doh_query(client, qname, "TLSA", dnssec=True)
    parsed_records: List[Dict[str, Any]] = []
    for ans in res.get("answers") or []:
        rec = parse_tlsa_rdata(ans)
        if rec:
            parsed_records.append(rec)

    present = len(parsed_records) > 0
    dnssec_ad = bool(res.get("ad"))
    valid_syntax = all(r["valid_syntax"] for r in parsed_records) if present else False
    return {
        "present": present,
        "host": clean_host,
        "qname": qname,
        "dnssec_ad": dnssec_ad,
        "provider": res.get("provider"),
        "valid_syntax": valid_syntax,
        "dane_without_dnssec": bool(present and not dnssec_ad),
        "records": parsed_records,
    }


# ---------------------------------------------------------------------------
# 5. ANS v2 `_ans-badge` Anti-Spoofing Host-Binding Check
# ---------------------------------------------------------------------------
def parse_ans_badge_txt(raw: str) -> Optional[Dict[str, str]]:
    """Parse `TXT _ans-badge.<host>` (`v=ans-badge1; version=v0.1.0; url=https://...`)."""
    cleaned = clean_txt_value(raw).strip()
    if not cleaned:
        return None
    low = cleaned.lower()
    if low.startswith(("v=spf1", "v=dmarc1")):
        return None
    fields: Dict[str, str] = {}
    for part in cleaned.split(";"):
        p = part.strip()
        if not p or "=" not in p:
            continue
        k, v = p.split("=", 1)
        fields[k.strip().lower()] = v.strip()
    if not fields:
        return None
    v_tag = fields.get("v", "").lower()
    if v_tag.startswith("ans-badge") or ("url" in fields and "ans" in low):
        fields["_raw"] = cleaned
        return fields
    return None


def host_from_ans_name(ans_name: str) -> str:
    """Extract normalized FQDN host from an ANS name (e.g., `ans://v0.1.0.travel.agenthaven.dev`)."""
    s = (ans_name or "").strip()
    if not s:
        return ""
    if "://" in s:
        # Preserve host portion even for custom scheme `ans://`
        after = s.split("://", 1)[1]
        host_part = after.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in host_part:
            host_part = host_part.rsplit("@", 1)[1]
        if ":" in host_part:
            host_part = host_part.split(":", 1)[0]
    else:
        host_part = s.split("/", 1)[0].split(":", 1)[0]
    host_part = host_part.strip().lower().rstrip(".")
    # Strip leading ANS semver prefix `v0.1.0.` -> `travel.agenthaven.dev`
    host_part = _ANS_VERSION_PREFIX_RE.sub("", host_part)
    return host_part


def extract_ans_receipt_binding(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Extract `ansName`, bound `receipt_host`, and `receipt_status` from an ANS transparency log JSON."""
    receipt_status = receipt.get("status")
    payload = receipt.get("payload") if isinstance(receipt.get("payload"), dict) else {}
    producer = payload.get("producer") if isinstance(payload.get("producer"), dict) else {}
    event = producer.get("event") if isinstance(producer.get("event"), dict) else {}
    event_agent = event.get("agent") if isinstance(event.get("agent"), dict) else {}
    payload_agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    top_agent = receipt.get("agent") if isinstance(receipt.get("agent"), dict) else {}

    ans_name: Optional[str] = None
    for cand in (
        event.get("ansName"),
        event.get("ans_name"),
        payload.get("ansName"),
        payload.get("ans_name"),
        receipt.get("ansName"),
        receipt.get("ans_name"),
    ):
        if isinstance(cand, str) and cand.strip():
            ans_name = cand.strip()
            break

    bound_hosts: List[str] = []
    for hcand in (
        event_agent.get("host"),
        event_agent.get("fqdn"),
        payload_agent.get("host"),
        payload_agent.get("fqdn"),
        top_agent.get("host"),
        top_agent.get("fqdn"),
        event.get("host"),
        event.get("fqdn"),
        payload.get("host"),
        payload.get("fqdn"),
        receipt.get("host"),
        receipt.get("fqdn"),
        receipt.get("domain"),
    ):
        if isinstance(hcand, str) and hcand.strip():
            norm = hcand.strip().lower().rstrip(".")
            if norm and norm not in bound_hosts:
                bound_hosts.append(norm)

    ans_derived_host = host_from_ans_name(ans_name) if ans_name else ""
    if ans_derived_host and ans_derived_host not in bound_hosts:
        bound_hosts.append(ans_derived_host)

    return {
        "receipt_status": str(receipt_status) if receipt_status is not None else None,
        "ans_name": ans_name,
        "receipt_host": bound_hosts[0] if bound_hosts else None,
        "all_bound_hosts": bound_hosts,
    }


def check_ans_badge(
    client: PoliteHttpClient,
    host: str,
    wc_txt: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Query `TXT _ans-badge.<host>`, fetch transparency receipt JSON, and verify strict FQDN binding."""
    dialed_host = host.strip().lower().rstrip(".")
    qname = f"_ans-badge.{dialed_host}"
    res = doh_query(client, qname, "TXT", dnssec=True)
    wc = wc_txt or set()

    parsed_badge: Optional[Dict[str, str]] = None
    for ans in res.get("answers") or []:
        if ans in wc:
            continue
        pb = parse_ans_badge_txt(ans)
        if pb:
            parsed_badge = pb
            break

    if not parsed_badge:
        return {
            "present": False,
            "host": dialed_host,
            "qname": qname,
            "dnssec_ad": bool(res.get("ad")),
            "raw_txt": None,
            "version": None,
            "receipt_url": None,
            "receipt_status": None,
            "ans_name": None,
            "receipt_host": None,
            "host_binding_status": "absent",
            "spoofed": False,
            "error": None,
        }

    receipt_url = parsed_badge.get("url")
    version = parsed_badge.get("version")
    inline_ans_name = parsed_badge.get("ansname")

    result: Dict[str, Any] = {
        "present": True,
        "host": dialed_host,
        "qname": qname,
        "dnssec_ad": bool(res.get("ad")),
        "raw_txt": parsed_badge.get("_raw"),
        "version": version,
        "receipt_url": receipt_url,
        "receipt_status": None,
        "ans_name": inline_ans_name,
        "receipt_host": None,
        "host_binding_status": "unverifiable",
        "spoofed": False,
        "error": None,
    }

    bound_hosts: List[str] = []
    if inline_ans_name:
        ih = host_from_ans_name(inline_ans_name)
        if ih:
            bound_hosts.append(ih)

    if receipt_url:
        u_parsed = urllib.parse.urlparse(receipt_url)
        if u_parsed.scheme.lower() in ("https", "http") and u_parsed.netloc:
            resp = client.get(
                receipt_url,
                timeout=5.5,
                max_bytes=262144,
                retries=0,
                accept="application/json",
            )
            ok, receipt_json, reason = _parse_json_body(resp)
            if ok and receipt_json:
                binding = extract_ans_receipt_binding(receipt_json)
                result["receipt_status"] = binding["receipt_status"]
                if binding["ans_name"]:
                    result["ans_name"] = binding["ans_name"]
                for bh in binding["all_bound_hosts"]:
                    if bh not in bound_hosts:
                        bound_hosts.append(bh)
            else:
                result["error"] = resp.error or reason
                if not bound_hosts:
                    result["host_binding_status"] = "fetch_error"
                    return result
        else:
            result["error"] = "invalid_receipt_url"

    if bound_hosts:
        result["receipt_host"] = bound_hosts[0]
        mismatched = [bh for bh in bound_hosts if bh != dialed_host]
        if mismatched:
            result["receipt_host"] = mismatched[0]
            result["host_binding_status"] = "host_mismatch"
            result["spoofed"] = True
        else:
            result["host_binding_status"] = "verified"
            result["spoofed"] = False

    return result


# ---------------------------------------------------------------------------
# 6. Complementary Chain-of-Trust Surface Detection (100% Passive, Zero Penalty)
# ---------------------------------------------------------------------------
def _extract_mandate_issuers(obj: Any) -> List[str]:
    """Recursively collect values under keys named `mandate_issuers` or ending in `.mandate_issuers`."""
    issuers: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and (k.lower() == "mandate_issuers" or k.lower().endswith("mandate_issuers")):
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, str) and item.strip():
                                issuers.append(item.strip())
                            elif isinstance(item, dict):
                                for ik in ("issuer", "id", "url", "name", "domain"):
                                    iv = item.get(ik)
                                    if isinstance(iv, str) and iv.strip():
                                        issuers.append(iv.strip())
                                        break
                    elif isinstance(v, str) and v.strip():
                        issuers.append(v.strip())
                else:
                    _walk(v)
        elif isinstance(node, list):
            for elem in node:
                _walk(elem)

    _walk(obj)
    # Deduplicate preserving order
    seen: Set[str] = set()
    uniq: List[str] = []
    for x in issuers:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq[:20]


def probe_chain_of_trust(
    client: PoliteHttpClient,
    hosts: Sequence[str],
    wc_txt: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Passively inspect complementary chain-of-trust surfaces across bounded hosts (zero FP penalties)."""
    ard_hits: List[Dict[str, Any]] = []
    ucp_hits: List[Dict[str, Any]] = []
    spiffe_bundle_hits: List[Dict[str, Any]] = []
    spiffe_svid_hits: List[Dict[str, Any]] = []
    agent_keys_hits: List[Dict[str, Any]] = []

    seen_hosts: Set[str] = set()
    bounded_hosts: List[str] = []
    for h in hosts:
        nh = (h or "").strip().lower().rstrip(".")
        if nh and nh not in seen_hosts:
            seen_hosts.add(nh)
            bounded_hosts.append(nh)
        if len(bounded_hosts) >= 6:
            break

    wc = wc_txt or set()

    for host in bounded_hosts:
        # 1. /.well-known/ard.json (Agentic Resource Discovery)
        r_ard = client.get(
            f"https://{host}/.well-known/ard.json",
            timeout=4.5,
            max_bytes=131072,
            retries=0,
            accept="application/ai-catalog+json, application/json",
        )
        ok_ard, p_ard, _ = _parse_json_body(r_ard)
        if ok_ard and p_ard and ("entries" in p_ard or "specVersion" in p_ard or "host" in p_ard):
            entries = p_ard.get("entries")
            ard_hits.append(
                {
                    "host": host,
                    "url": r_ard.final_url or f"https://{host}/.well-known/ard.json",
                    "spec_version": p_ard.get("specVersion") or p_ard.get("version"),
                    "entries_count": len(entries) if isinstance(entries, list) else 0,
                }
            )

        # 2. /.well-known/ucp (Universal Commerce Protocol)
        r_ucp = client.get(
            f"https://{host}/.well-known/ucp",
            timeout=4.5,
            max_bytes=131072,
            retries=0,
            accept="application/json",
        )
        ok_ucp, p_ucp, _ = _parse_json_body(r_ucp)
        if ok_ucp and p_ucp and ("ucp" in p_ucp or "mandate_issuers" in p_ucp or "services" in p_ucp):
            ucp_obj = p_ucp.get("ucp") if isinstance(p_ucp.get("ucp"), dict) else p_ucp
            services_raw = ucp_obj.get("services") if isinstance(ucp_obj, dict) else None
            services = sorted(services_raw.keys())[:10] if isinstance(services_raw, dict) else []
            keys_raw = p_ucp.get("keys") or (ucp_obj.get("keys") if isinstance(ucp_obj, dict) else None)
            ucp_hits.append(
                {
                    "host": host,
                    "url": r_ucp.final_url or f"https://{host}/.well-known/ucp",
                    "version": ucp_obj.get("version") if isinstance(ucp_obj, dict) else None,
                    "services": services,
                    "mandate_issuers": _extract_mandate_issuers(p_ucp),
                    "keys_count": len(keys_raw) if isinstance(keys_raw, list) else 0,
                }
            )

        # 3. /.well-known/spiffe-bundle.json
        r_sb = client.get(
            f"https://{host}/.well-known/spiffe-bundle.json",
            timeout=4.5,
            max_bytes=131072,
            retries=0,
            accept="application/json",
        )
        ok_sb, p_sb, _ = _parse_json_body(r_sb)
        if ok_sb and p_sb and isinstance(p_sb.get("keys"), list) and len(p_sb["keys"]) > 0:
            spiffe_bundle_hits.append(
                {
                    "host": host,
                    "url": r_sb.final_url or f"https://{host}/.well-known/spiffe-bundle.json",
                    "keys_count": len(p_sb["keys"]),
                }
            )

        # 4. /.well-known/spiffe-svid.json
        r_sv = client.get(
            f"https://{host}/.well-known/spiffe-svid.json",
            timeout=4.5,
            max_bytes=131072,
            retries=0,
            accept="application/json",
        )
        ok_sv, p_sv, _ = _parse_json_body(r_sv)
        if ok_sv and p_sv and (p_sv.get("spiffe_id") or p_sv.get("instance_id") or p_sv.get("public_jwk")):
            spiffe_svid_hits.append(
                {
                    "host": host,
                    "url": r_sv.final_url or f"https://{host}/.well-known/spiffe-svid.json",
                    "spiffe_id": p_sv.get("spiffe_id"),
                    "instance_id": p_sv.get("instance_id"),
                }
            )

        # 5. TXT _agent-keys.<host> (`v=agentkey1`)
        ak_qname = f"_agent-keys.{host}"
        ak_res = doh_query(client, ak_qname, "TXT", dnssec=True)
        ak_vals: List[str] = []
        for raw_txt in ak_res.get("answers") or []:
            if raw_txt in wc:
                continue
            cleaned = clean_txt_value(raw_txt)
            low = cleaned.lower()
            if low.startswith(("v=spf1", "v=dmarc1")):
                continue
            if "v=agentkey1" in low or ("k=" in low and "p=" in low):
                ak_vals.append(cleaned)
        if ak_vals:
            agent_keys_hits.append(
                {
                    "host": host,
                    "qname": ak_qname,
                    "dnssec_ad": bool(ak_res.get("ad")),
                    "records": ak_vals,
                }
            )

    surfaces: List[str] = []
    if ard_hits:
        surfaces.append("ard")
    if ucp_hits:
        surfaces.append("ucp")
    if spiffe_bundle_hits:
        surfaces.append("spiffe_bundle")
    if spiffe_svid_hits:
        surfaces.append("spiffe_svid")
    if agent_keys_hits:
        surfaces.append("agent_keys_txt")

    return {
        "ard": ard_hits,
        "ucp": ucp_hits,
        "spiffe_bundle": spiffe_bundle_hits,
        "spiffe_svid": spiffe_svid_hits,
        "agent_keys_txt": agent_keys_hits,
        "surfaces_detected": surfaces,
    }


# ---------------------------------------------------------------------------
# 7. Main DNS-AID & ANS v2 Wire-Level Linter Entry Point
# ---------------------------------------------------------------------------
def _filter_non_wildcard_txt(answers: Sequence[str], wc_txt: Set[str]) -> List[str]:
    out: List[str] = []
    for raw in answers:
        if raw in wc_txt:
            continue
        cleaned = clean_txt_value(raw)
        if cleaned and not cleaned.lower().startswith(("v=spf1", "v=dmarc1")):
            out.append(cleaned)
    return out


def lint_dns_aid(
    client: PoliteHttpClient,
    domain: str,
    verified_domains: Optional[Sequence[str]] = None,
    extra_hosts: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Run full wire-level passive DNS-AID (draft-02), DANE TLSA, and ANS v2 badge validation."""
    primary = registrable_domain(domain)
    v_domains = list(verified_domains) if verified_domains else [primary]

    # Apex DNSSEC check (A primary, NS fallback if apex A has NODATA without AD)
    apex_a = doh_query(client, primary, "A", dnssec=True)
    apex_dnssec_ad = bool(apex_a.get("ad"))
    if not apex_dnssec_ad and not apex_a.get("answers"):
        apex_ns = doh_query(client, primary, "NS", dnssec=True)
        if apex_ns.get("ad"):
            apex_dnssec_ad = True

    # Wildcard TXT baseline
    wc_txt = set(doh_query(client, f"_agent-nx-9f8e7d.{primary}", "TXT", dnssec=False).get("answers") or [])

    # 1. Query `_index._agents.<domain>` (SVCB primary + TXT fallback/companion)
    idx_qname = f"_index._agents.{primary}"
    idx_svcb_res = doh_query(client, idx_qname, "SVCB", dnssec=True)
    idx_txt_res = doh_query(client, idx_qname, "TXT", dnssec=True)

    index_svcb: List[Dict[str, Any]] = []
    for raw in idx_svcb_res.get("answers") or []:
        parsed = parse_svcb_rdata(raw)
        if parsed:
            index_svcb.append(parsed)

    index_txt = _filter_non_wildcard_txt(idx_txt_res.get("answers") or [], wc_txt)
    indexed_agents = parse_dns_aid_index_txt(index_txt)
    index_dnssec_ad = bool(
        (index_svcb and idx_svcb_res.get("ad")) or (indexed_agents and idx_txt_res.get("ad"))
    )

    # Check dedicated `catalog.<domain>` separation
    catalog_separated = False
    catalog_host: Optional[str] = None
    for sv in index_svcb:
        tgt = sv.get("target") or ""
        if tgt and tgt != "." and (tgt == f"catalog.{primary}" or tgt.startswith("catalog.")):
            catalog_separated = True
            catalog_host = tgt
            break

    # Also check `_index._agents.catalog.<domain>` if no index was found on apex
    if not index_svcb and not indexed_agents:
        cat_idx_qname = f"_index._agents.catalog.{primary}"
        cat_svcb_res = doh_query(client, cat_idx_qname, "SVCB", dnssec=True)
        cat_txt_res = doh_query(client, cat_idx_qname, "TXT", dnssec=True)
        cat_svcb = [p for raw in (cat_svcb_res.get("answers") or []) if (p := parse_svcb_rdata(raw))]
        cat_txt = _filter_non_wildcard_txt(cat_txt_res.get("answers") or [], wc_txt)
        cat_agents = parse_dns_aid_index_txt(cat_txt)
        if cat_svcb or cat_agents:
            catalog_separated = True
            catalog_host = f"catalog.{primary}"
            index_svcb.extend(cat_svcb)
            index_txt.extend(cat_txt)
            indexed_agents.extend(cat_agents)
            if (cat_svcb and cat_svcb_res.get("ad")) or (cat_agents and cat_txt_res.get("ad")):
                index_dnssec_ad = True

    index_found = bool(index_svcb or indexed_agents)
    index_source: Optional[str] = None
    if index_svcb and indexed_agents:
        index_source = "svcb+txt"
    elif index_svcb:
        index_source = "svcb"
    elif indexed_agents:
        index_source = "txt"

    # 2. Discover & verify per-agent SVCB records (live `<agent>.<domain>` + draft-02 `_agents` labels)
    agent_records: List[Dict[str, Any]] = []
    probed_targets: Set[str] = set()
    dane_tlsa_hosts: List[str] = []
    dane_without_dnssec_hosts: List[str] = []
    card_hash_verified_count = 0
    card_hash_mismatch_hosts: List[str] = []
    ans_badges_checked: List[Dict[str, Any]] = []
    ans_badge_verified_hosts: List[str] = []
    spoofed_ans_badge_hosts: List[Dict[str, Any]] = []
    checked_ans_hosts: Set[str] = set()
    checked_tlsa_hosts: Set[str] = set()

    def _record_ans_badge(badge: Dict[str, Any]) -> None:
        h = badge["host"]
        if h in checked_ans_hosts:
            return
        checked_ans_hosts.add(h)
        if badge["present"]:
            ans_badges_checked.append(badge)
            if badge["spoofed"]:
                spoofed_ans_badge_hosts.append(
                    {
                        "host": h,
                        "receipt_host": badge["receipt_host"],
                        "ans_name": badge["ans_name"],
                        "receipt_url": badge["receipt_url"],
                        "receipt_status": badge["receipt_status"],
                        "dnssec_ad": badge["dnssec_ad"],
                    }
                )
            elif badge["host_binding_status"] == "verified":
                ans_badge_verified_hosts.append(h)

    def _record_tlsa(tlsa: Dict[str, Any]) -> None:
        h = tlsa["host"]
        if h in checked_tlsa_hosts:
            return
        checked_tlsa_hosts.add(h)
        if tlsa["present"]:
            dane_tlsa_hosts.append(h)
            if tlsa["dane_without_dnssec"]:
                dane_without_dnssec_hosts.append(h)

    for entry in indexed_agents[:12]:
        aname = entry["name"]
        aproto = entry["protocol"]
        candidate_qnames = [
            f"{aname}.{primary}",
            f"{aname}._{aproto}._agents.{primary}",
            f"_{aname}._{aproto}._agents.{primary}",
        ]
        matched_qname: Optional[str] = None
        matched_svcb: Optional[Dict[str, Any]] = None
        matched_ad = False
        for cq in candidate_qnames:
            sv_res = doh_query(client, cq, "SVCB", dnssec=True)
            for raw in sv_res.get("answers") or []:
                parsed = parse_svcb_rdata(raw)
                if parsed:
                    matched_qname = cq
                    matched_svcb = parsed
                    matched_ad = bool(sv_res.get("ad"))
                    break
            if matched_svcb:
                break

        if not matched_svcb or not matched_qname:
            continue

        # Determine target host
        raw_target = matched_svcb.get("target") or "."
        if raw_target == ".":
            target_host = f"{aname}.{primary}" if "._agents." in matched_qname else matched_qname
        else:
            target_host = raw_target
        probed_targets.add(target_host)

        # Optional TXT metadata on the matched qname
        txt_res = doh_query(client, matched_qname, "TXT", dnssec=True)
        txt_meta = _filter_non_wildcard_txt(txt_res.get("answers") or [], wc_txt)

        # Passive card-tampering check (key65400 vs key65401)
        card_ver = verify_card_digest(client, matched_svcb.get("cap"), matched_svcb.get("cap_sha256"))
        if card_ver["status"] == "verified":
            card_hash_verified_count += 1
        elif card_ver["status"] == "mismatch":
            card_hash_mismatch_hosts.append(target_host)

        # DANE TLSA on target_host
        tlsa = probe_dane_tlsa(client, target_host)
        _record_tlsa(tlsa)

        # ANS v2 _ans-badge on target_host
        badge = check_ans_badge(client, target_host, wc_txt=wc_txt)
        _record_ans_badge(badge)

        agent_records.append(
            {
                "agent_name": aname,
                "protocol": aproto,
                "qname": matched_qname,
                "target_host": target_host,
                "dnssec_ad": matched_ad,
                "svcb": matched_svcb,
                "txt_metadata": txt_meta,
                "card_verification": card_ver,
                "dane_tlsa": tlsa,
                "ans_badge": badge,
            }
        )

    # Also check DANE TLSA and ANS badge on catalog_host (if separated)
    if catalog_host and catalog_host not in checked_tlsa_hosts:
        _record_tlsa(probe_dane_tlsa(client, catalog_host))
    if catalog_host and catalog_host not in checked_ans_hosts:
        _record_ans_badge(check_ans_badge(client, catalog_host, wc_txt=wc_txt))

    # Check ANS badge on apex domain + any extra confirmed live first-party hosts (capped)
    extra_check_hosts: List[str] = [primary]
    for eh in (extra_hosts or []):
        nh = (eh or "").strip().lower().rstrip(".")
        if nh and nh not in extra_check_hosts and nh not in probed_targets:
            extra_check_hosts.append(nh)
    for ch in extra_check_hosts[:5]:
        if ch not in checked_ans_hosts:
            _record_ans_badge(check_ans_badge(client, ch, wc_txt=wc_txt))

    # Build verified first-party agent FQDNs (exclude spoofed or digest-mismatched hosts)
    spoofed_set = {s["host"] for s in spoofed_ans_badge_hosts}
    mismatch_set = set(card_hash_mismatch_hosts)
    verified_fqdns: List[str] = []
    for rec in agent_records:
        th = rec["target_host"]
        if (
            th
            and host_matches_any(th, v_domains)
            and th not in spoofed_set
            and th not in mismatch_set
            and th not in verified_fqdns
        ):
            verified_fqdns.append(th)
    if (
        catalog_host
        and host_matches_any(catalog_host, v_domains)
        and catalog_host not in spoofed_set
        and catalog_host not in verified_fqdns
    ):
        verified_fqdns.append(catalog_host)

    return {
        "domain": primary,
        "apex_dnssec_ad": apex_dnssec_ad,
        "index_found": index_found,
        "index_source": index_source,
        "index_dnssec_ad": index_dnssec_ad,
        "index_svcb": index_svcb,
        "index_txt": index_txt,
        "catalog_separated": catalog_separated,
        "catalog_host": catalog_host,
        "indexed_agents": indexed_agents,
        "agent_records": agent_records,
        "verified_first_party_agent_fqdns": verified_fqdns,
        "card_hash_verified_count": card_hash_verified_count,
        "card_hash_mismatch_hosts": sorted(mismatch_set),
        "dane_tlsa_hosts": sorted(set(dane_tlsa_hosts)),
        "dane_without_dnssec_hosts": sorted(set(dane_without_dnssec_hosts)),
        "ans_badges_checked": ans_badges_checked,
        "ans_badge_verified_hosts": sorted(set(ans_badge_verified_hosts)),
        "spoofed_ans_badge_hosts": spoofed_ans_badge_hosts,
    }


def probe_lookalike_ans_badges(
    client: PoliteHttpClient,
    lookalike_domain: str,
) -> List[Dict[str, Any]]:
    """V3 helper: passively detect copied/spoofed `_ans-badge` records on a lookalike domain
    and any agent subdomains advertised via `_index._agents.<lookalike_domain>`.
    """
    dom = lookalike_domain.strip().lower().rstrip(".")
    hosts_to_check: List[str] = [dom]

    # Discover agent hosts advertised in `_index._agents.<lookalike>` (e.g., `travel.agent-haven.dev`)
    idx_txt = doh_query(client, f"_index._agents.{dom}", "TXT", dnssec=True)
    for item in parse_dns_aid_index_txt(idx_txt.get("answers") or [])[:6]:
        ahost = f"{item['name']}.{dom}"
        if ahost not in hosts_to_check:
            hosts_to_check.append(ahost)

    spoofed: List[Dict[str, Any]] = []
    for host in hosts_to_check:
        badge = check_ans_badge(client, host)
        if badge.get("spoofed"):
            spoofed.append(
                {
                    "domain": dom,
                    "host": badge["host"],
                    "receipt_host": badge["receipt_host"],
                    "ans_name": badge["ans_name"],
                    "receipt_url": badge["receipt_url"],
                    "receipt_status": badge["receipt_status"],
                    "dnssec_ad": badge["dnssec_ad"],
                }
            )
    return spoofed
