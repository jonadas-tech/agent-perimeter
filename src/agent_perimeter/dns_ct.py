"""Passive DNS-over-HTTPS (with DNSSEC AD), DNS-AID (_agent/_mcp SVCB/TXT/SRV),
multi-provider Certificate Transparency (CertSpotter + crt.sh fallback), live TLS SAN,
and first-party sibling-domain discovery.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse

from .http_client import PoliteHttpClient

# Common multi-part public suffixes for registrable-domain extraction without external deps
_MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.br", "org.br", "net.br", "gov.br",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "co.in", "com.mx", "com.sg", "com.hk", "co.kr", "com.cn",
    "co.nz", "co.za", "com.ar", "com.tw", "com.tr", "co.il",
}


def registrable_domain(host: str) -> str:
    """Extract eTLD+1 registrable domain from a hostname (dependency-free)."""
    h = host.strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    if ":" in h:
        h = h.split(":", 1)[0]
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    tail2 = ".".join(parts[-2:])
    if tail2 in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


def host_matches_domain(host: str, domain: str) -> bool:
    h = host.strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    d = domain.strip().lower().rstrip(".")
    return bool(h and d and (h == d or h.endswith("." + d)))


def host_matches_any(host: str, domains: List[str]) -> bool:
    return any(host_matches_domain(host, d) for d in domains)


def url_host(url_str: str) -> str:
    if not url_str:
        return ""
    s = url_str.strip()
    if "://" not in s and "." in s and not s.startswith("/"):
        s = "https://" + s
    try:
        return (urllib.parse.urlparse(s).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def url_matches_any(url_str: str, domains: List[str]) -> bool:
    h = url_host(url_str)
    return bool(h and host_matches_any(h, domains))


# ---------------------------------------------------------------------------
# Passive DoH (with DNSSEC AD bit and Cloudflare fallback)
# ---------------------------------------------------------------------------
_RTYPE_NUMBERS: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "SVCB": 64,
    "HTTPS": 65,
}

_DNS_AID_TXT_RE = re.compile(
    r"(v=aid|v=dns-aid|protocol=|alpn=|uri=|endpoint=|mcp|a2a|agent[_-]?card|agent=)",
    re.IGNORECASE,
)


def doh_query(
    client: PoliteHttpClient,
    fqdn: str,
    rtype: str,
    dnssec: bool = True,
) -> Dict[str, Any]:
    """Query a single DNS record type passively via Google DoH (fallback: Cloudflare DoH)."""
    do_param = "&do=1" if dnssec else ""
    expected_type_num = _RTYPE_NUMBERS.get(rtype.upper())
    providers = [
        (
            "dns.google",
            f"https://dns.google/resolve?name={urllib.parse.quote(fqdn)}&type={urllib.parse.quote(rtype)}{do_param}",
            {"Accept": "application/dns-json"},
        ),
        (
            "cloudflare-dns.com",
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(fqdn)}&type={urllib.parse.quote(rtype)}{do_param}",
            {"Accept": "application/dns-json"},
        ),
    ]
    for bucket, url, headers in providers:
        resp = client.get(url, timeout=4.5, retries=0, bucket=bucket, extra_headers=headers)
        if resp.status != 200:
            continue
        try:
            data = json.loads(resp.body_text)
        except Exception:
            continue
        answers: List[str] = []
        for ans in data.get("Answer", []) or []:
            ans_type = int(ans.get("type", 0) or 0)
            # Skip RRSIG (46) and mismatched intermediate CNAMEs when querying SVCB/TXT/SRV
            if ans_type == 46:
                continue
            if expected_type_num is not None and ans_type != expected_type_num:
                # Allow CNAME records only when explicitly querying CNAME (or A/AAAA resolution)
                if not (rtype.upper() in ("A", "AAAA") and ans_type == 5):
                    continue
            val = str(ans.get("data", "")).strip()
            if val and val not in answers:
                answers.append(val)
        return {
            "ok": True,
            "provider": bucket,
            "status": int(data.get("Status", -1)),
            "ad": bool(data.get("AD", False)),
            "answers": answers,
        }
    return {"ok": False, "provider": None, "status": -1, "ad": False, "answers": []}


def doh_resolve(
    client: PoliteHttpClient,
    fqdn: str,
    rtypes: Tuple[str, ...] = ("A", "AAAA", "CNAME"),
    dnssec: bool = True,
) -> Dict[str, Any]:
    records: Dict[str, List[str]] = {}
    statuses: Dict[str, int] = {}
    ad_flags: Dict[str, bool] = {}
    for rtype in rtypes:
        res = doh_query(client, fqdn, rtype, dnssec=dnssec)
        statuses[rtype] = res["status"]
        ad_flags[rtype] = res["ad"]
        if res["answers"]:
            records[rtype] = res["answers"]
    has_ip_or_cname = bool(records.get("A") or records.get("AAAA") or records.get("CNAME"))
    has_delegation = has_ip_or_cname or bool(records.get("NS"))
    return {
        "fqdn": fqdn,
        "dns_status": statuses,
        "dnssec_ad": any(ad_flags.values()),
        "resolves": has_ip_or_cname,
        "delegated": has_delegation,
        "records": records,
    }


def probe_dns_aid(client: PoliteHttpClient, domain: str) -> Dict[str, Any]:
    """Passively audit IETF DNS-AID / open DNS agent discovery records & DNSSEC."""
    apex_check = doh_query(client, domain, "A", dnssec=True)
    apex_dnssec = bool(apex_check.get("ad"))

    # Wildcard TXT baseline to exclude defensive wildcard `*.domain TXT "v=spf1 -all"`
    wc_txt = set(doh_query(client, f"_agent-nx-9f8e7d.{domain}", "TXT", dnssec=False).get("answers") or [])

    targets = [
        (f"_agent.{domain}", ("SVCB", "TXT", "SRV")),
        (f"_mcp.{domain}", ("SVCB", "TXT", "SRV")),
        (f"_mcp._tcp.{domain}", ("SRV", "TXT")),
    ]
    records_found: List[Dict[str, Any]] = []
    dns_aid_dnssec = False
    for qname, rtypes in targets:
        for rtype in rtypes:
            res = doh_query(client, qname, rtype, dnssec=True)
            vals = list(res["answers"])
            if rtype == "TXT":
                vals = [
                    v
                    for v in vals
                    if v not in wc_txt
                    and not v.strip("\"' ").lower().startswith(("v=spf1", "v=dmarc1"))
                    and _DNS_AID_TXT_RE.search(v)
                ]
            if vals:
                if res["ad"]:
                    dns_aid_dnssec = True
                records_found.append(
                    {
                        "qname": qname,
                        "rtype": rtype,
                        "values": vals,
                        "dnssec_ad": res["ad"],
                        "provider": res["provider"],
                    }
                )

    return {
        "apex_dnssec_ad": apex_dnssec,
        "dns_aid_present": len(records_found) > 0,
        "dns_aid_dnssec_ad": dns_aid_dnssec,
        "records": records_found,
    }


# ---------------------------------------------------------------------------
# Passive Certificate Transparency (CertSpotter primary + crt.sh fallback)
# ---------------------------------------------------------------------------
_AGENT_HOST_RE = re.compile(
    r"^(?:mcp|mcps|agents|a2a|mcp-[a-z0-9-]+|[a-z0-9-]+-mcp|agents-[a-z0-9-]+)\.",
    re.IGNORECASE,
)


def _is_agent_subdomain(hostname: str, domain: str) -> bool:
    h = hostname.lower().lstrip("*.")
    if not host_matches_domain(h, domain) or h == domain.lower():
        return False
    # Explicitly drop legacy `agent.<domain>` telemetry/monitoring hosts
    if h == f"agent.{domain.lower()}":
        return False
    return bool(_AGENT_HOST_RE.match(h))


def query_certspotter(client: PoliteHttpClient, domain: str) -> Dict[str, Any]:
    """Query CertSpotter public CT issuance API for agent-related subdomains."""
    if client.circuit_is_open("api.certspotter.com"):
        return {
            "provider": "certspotter",
            "ok": False,
            "error": "certspotter_cooldown",
            "agent_subdomains": [],
            "cert_count": 0,
            "sample_certs": [],
        }

    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={urllib.parse.quote(domain)}&include_subdomains=true&expand=dns_names"
    )
    headers: Dict[str, str] = {}
    if client.certspotter_token:
        headers["Authorization"] = f"Bearer {client.certspotter_token}"

    resp = client.get(
        url,
        timeout=6.0,
        max_bytes=2097152,
        retries=0,
        bucket="api.certspotter.com",
        extra_headers=headers,
    )
    if resp.status == 429:
        # Anonymous quota reached; trip cooldown cleanly so we never hammer CertSpotter
        client.circuit_trip("api.certspotter.com", cooldown_s=300.0)
        return {
            "provider": "certspotter",
            "ok": False,
            "http_status": 429,
            "error": "http_429_rate_limited",
            "agent_subdomains": [],
            "cert_count": 0,
            "sample_certs": [],
        }
    if resp.status != 200:
        client.circuit_record_failure("api.certspotter.com", threshold=3, cooldown_s=90.0)
        return {
            "provider": "certspotter",
            "ok": False,
            "http_status": resp.status,
            "error": resp.error or f"http_{resp.status}",
            "agent_subdomains": [],
            "cert_count": 0,
            "sample_certs": [],
        }

    client.circuit_record_success("api.certspotter.com")
    try:
        rows = json.loads(resp.body_text)
        if not isinstance(rows, list):
            rows = []
    except Exception as e:
        return {
            "provider": "certspotter",
            "ok": False,
            "http_status": 200,
            "error": f"json_error: {e}",
            "agent_subdomains": [],
            "cert_count": 0,
            "sample_certs": [],
        }

    agent_hosts: Set[str] = set()
    samples: List[Dict[str, Any]] = []
    for row in rows:
        dns_names = row.get("dns_names") or []
        matched = [n.lower().lstrip("*.") for n in dns_names if isinstance(n, str) and _is_agent_subdomain(n, domain)]
        if matched:
            agent_hosts.update(matched)
            if len(samples) < 8:
                samples.append(
                    {
                        "id": str(row.get("id", "")),
                        "dns_names": matched[:10],
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                    }
                )
    return {
        "provider": "certspotter",
        "ok": True,
        "http_status": 200,
        "total_issuances_inspected": len(rows),
        "agent_subdomains": sorted(agent_hosts),
        "cert_count": len(samples),
        "sample_certs": samples,
    }


def query_crtsh_fallback(client: PoliteHttpClient, query: str, domain: str) -> Dict[str, Any]:
    """Bounded optional crt.sh fallback with circuit breaker (never blocks)."""
    if client.circuit_is_open("crt.sh"):
        return {
            "provider": "crt.sh",
            "ok": False,
            "error": "crtsh_circuit_breaker_cooldown",
            "agent_subdomains": [],
            "cert_count": 0,
            "sample_certs": [],
        }

    url = f"https://crt.sh/?q={urllib.parse.quote(query)}&output=json"
    resp = client.get(url, timeout=4.0, max_bytes=1048576, retries=0, bucket="crt.sh")
    if resp.status != 200:
        client.circuit_record_failure("crt.sh", threshold=2, cooldown_s=90.0)
        return {
            "provider": "crt.sh",
            "ok": False,
            "http_status": resp.status,
            "error": resp.error or f"http_{resp.status}",
            "agent_subdomains": [],
            "cert_count": 0,
            "sample_certs": [],
        }

    client.circuit_record_success("crt.sh")
    body = resp.body_text.strip()
    rows: List[Dict[str, Any]] = []
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, list):
                rows = parsed
        except Exception:
            if body.startswith("["):
                idx = body.rfind("},")
                if idx == -1:
                    idx = body.rfind("}")
                if idx > 1:
                    try:
                        parsed = json.loads(body[: idx + 1] + "]")
                        if isinstance(parsed, list):
                            rows = parsed
                    except Exception:
                        pass

    agent_hosts: Set[str] = set()
    samples: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    for r in rows[:200]:
        cid = str(r.get("id", ""))
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        nv = str(r.get("name_value") or "")
        names = [line.strip().lower().lstrip("*.") for line in nv.splitlines() if line.strip()]
        matched = [n for n in names if _is_agent_subdomain(n, domain)]
        if matched:
            agent_hosts.update(matched)
            if len(samples) < 5:
                samples.append(
                    {
                        "id": cid,
                        "dns_names": matched[:10],
                        "issuer_name": r.get("issuer_name"),
                        "not_before": r.get("not_before"),
                        "not_after": r.get("not_after"),
                    }
                )
    return {
        "provider": "crt.sh",
        "ok": True,
        "http_status": 200,
        "agent_subdomains": sorted(agent_hosts),
        "cert_count": len(seen_ids),
        "sample_certs": samples,
    }


def query_ct_agent_subdomains(client: PoliteHttpClient, domain: str) -> Dict[str, Any]:
    """Multi-provider CT lookup: CertSpotter first, bounded crt.sh fallback for mcp.<domain>."""
    cs = query_certspotter(client, domain)
    if cs.get("ok"):
        return cs
    fb = query_crtsh_fallback(client, f"mcp.{domain}", domain)
    fb["primary_error"] = cs.get("error")
    return fb


# ---------------------------------------------------------------------------
# Live Passive TLS Leaf Certificate & SAN Inspection
# ---------------------------------------------------------------------------
def inspect_tls_cert(hostname: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Passively inspect live TLS leaf certificate and SubjectAltNames on port 443."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() or {}
                subject = {k: v for tup in cert.get("subject", ()) for k, v in tup}
                issuer = {k: v for tup in cert.get("issuer", ()) for k, v in tup}
                sans = [v.lower() for typ, v in cert.get("subjectAltName", ()) if typ == "DNS"]
                return {
                    "hostname": hostname,
                    "tls_ok": True,
                    "verified": True,
                    "subject_cn": subject.get("commonName"),
                    "issuer_o": issuer.get("organizationName"),
                    "issuer_cn": issuer.get("commonName"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "sans": sans[:40],
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "hostname": hostname,
            "tls_ok": True,
            "verified": False,
            "error": f"SSLCertVerificationError: {e}",
            "sans": [],
        }
    except Exception as e:
        return {
            "hostname": hostname,
            "tls_ok": False,
            "verified": False,
            "error": f"{type(e).__name__}: {e}",
            "sans": [],
        }


# ---------------------------------------------------------------------------
# Automatic Verified Sibling-Domain Discovery
# ---------------------------------------------------------------------------
def discover_sibling_domains(
    client: PoliteHttpClient,
    domain: str,
    brand: str,
    aliases: List[str],
    seed_siblings: Optional[List[str]] = None,
) -> Tuple[List[str], Dict[str, Any]]:
    """Passively discover verified first-party sibling domains (e.g., notion.so <-> notion.com,
    sentry.io <-> sentry.dev, datadoghq.com <-> datadog.com).
    """
    primary = registrable_domain(domain)
    verified: Set[str] = {primary}
    for s in seed_siblings or []:
        reg = registrable_domain(s)
        if reg:
            verified.add(reg)

    evidence: Dict[str, Any] = {"redirect_siblings": [], "tls_san_siblings": [], "com_redirect_checked": None}
    alias_lows = {a.lower() for a in [brand, *aliases] if len(a) >= 3}

    # 1. Check apex + www redirect target
    for probe_url in (f"https://{primary}/", f"https://www.{primary}/"):
        resp = client.get(probe_url, timeout=5.0, max_bytes=16384, retries=0)
        if resp.status and resp.final_url:
            f_reg = registrable_domain(url_host(resp.final_url))
            if f_reg and f_reg != primary and any(a in f_reg for a in alias_lows):
                verified.add(f_reg)
                evidence["redirect_siblings"].append({"from": probe_url, "to": resp.final_url, "domain": f_reg})

    # 2. Check TLS SANs on primary domain for sibling brand domains (excluding generic CDN SANs)
    tls_apex = inspect_tls_cert(primary, timeout=4.5)
    for san in tls_apex.get("sans") or []:
        s_reg = registrable_domain(san)
        if s_reg and s_reg != primary and any(a in s_reg.split(".")[0] for a in alias_lows):
            verified.add(s_reg)
            if s_reg not in evidence["tls_san_siblings"]:
                evidence["tls_san_siblings"].append(s_reg)

    # 3. If primary is <brand>.<non-com> (e.g., notion.so, sentry.io, linear.app) or ends with hq.com,
    # check if <brand>.com redirects straight into primary!
    candidate_coms: List[str] = []
    if not primary.endswith(".com"):
        candidate_coms.append(f"{brand.lower()}.com")
    elif primary.endswith("hq.com"):
        candidate_coms.append(primary.replace("hq.com", ".com"))

    for cand in candidate_coms:
        if cand in verified:
            continue
        r = client.get(f"https://{cand}/", timeout=4.5, max_bytes=8192, retries=0)
        evidence["com_redirect_checked"] = {"candidate": cand, "final_url": r.final_url, "status": r.status}
        if r.status and url_matches_any(r.final_url, [primary]):
            verified.add(cand)
            evidence["redirect_siblings"].append({"from": f"https://{cand}/", "to": r.final_url, "domain": cand})

    return sorted(verified), evidence
