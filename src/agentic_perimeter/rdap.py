"""100% passive RFC 9083 RDAP domain-age & registrar profiler (stdlib only).

Profiles third-party hosted MCP proxy domains and active/phishing/spoofed-badge
lookalike domains to surface Newly Observed Domains (NOD <30d / <90d) and
registrar provenance without active scanning or external dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import threading
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from .dns_ct import registrable_domain, url_host
from .http_client import PoliteHttpClient

IANA_RDAP_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Reliable built-in fallback map if IANA bootstrap is unreachable or offline
FALLBACK_RDAP_SERVERS: Dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "dev": "https://pubapi.registry.google/rdap/",
    "app": "https://pubapi.registry.google/rdap/",
    "io": "https://rdap.identitydigital.services/rdap/",
    "ai": "https://rdap.identitydigital.services/rdap/",
    "sh": "https://rdap.identitydigital.services/rdap/",
    "me": "https://rdap.identitydigital.services/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "run": "https://rdap.identitydigital.services/rdap/",
    "tools": "https://rdap.identitydigital.services/rdap/",
    "co": "https://rdap.registry.co/rdap/",
    "cloud": "https://rdap.registry.cloud/rdap/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "so": "https://rdap.centralnic.com/so/",
    "tech": "https://rdap.centralnic.com/tech/",
    "site": "https://rdap.centralnic.com/site/",
    "online": "https://rdap.centralnic.com/online/",
    "store": "https://rdap.centralnic.com/store/",
    "gg": "https://rdap.channelisles.net/",
    "uk": "https://rdap.nominet.uk/uk/",
    "ca": "https://rdap.ca.fury.ca/rdap/",
    "de": "https://rdap.denic.de/",
    "fr": "https://rdap.nic.fr/",
    "nl": "https://rdap.sidn.nl/",
    "ch": "https://rdap.nic.ch/",
    "br": "https://rdap.registro.br/",
    "eu": "https://rdap.eurid.eu/",
    "us": "https://rdap.nic.us/",
    "biz": "https://rdap.nic.biz/",
}

_CACHE_LOCK = threading.Lock()
_BOOTSTRAP_FETCHED = False
_BOOTSTRAP_MAP: Dict[str, str] = {}
_DOMAIN_CACHE: Dict[str, Dict[str, Any]] = {}


def clear_rdap_caches() -> None:
    """Clear in-memory IANA bootstrap and per-domain RDAP caches (useful for tests)."""
    global _BOOTSTRAP_FETCHED
    with _CACHE_LOCK:
        _BOOTSTRAP_FETCHED = False
        _BOOTSTRAP_MAP.clear()
        _DOMAIN_CACHE.clear()


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _normalize_rdap_base(url: str) -> str:
    s = url.strip()
    if not s.endswith("/"):
        s += "/"
    return s


def _parse_iana_bootstrap(payload: Any) -> Dict[str, str]:
    """Parse RFC 9224 / IANA RDAP DNS bootstrap JSON into {tld: https_base_url}."""
    mapping: Dict[str, str] = {}
    if not isinstance(payload, dict):
        return mapping
    services = payload.get("services")
    if not isinstance(services, list):
        return mapping
    for entry in services:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        chosen = ""
        for u in urls:
            if isinstance(u, str) and u.lower().startswith("https://"):
                chosen = _normalize_rdap_base(u)
                break
        if not chosen:
            for u in urls:
                if isinstance(u, str) and u.lower().startswith("http://"):
                    chosen = _normalize_rdap_base(u)
                    break
        if not chosen:
            continue
        for tld in tlds:
            if isinstance(tld, str):
                clean = tld.strip().lower().lstrip(".")
                if clean:
                    mapping[clean] = chosen
    return mapping


def get_rdap_bootstrap(client: PoliteHttpClient, force_refresh: bool = False) -> Dict[str, str]:
    """Fetch and cache the IANA RDAP DNS bootstrap registry once per process."""
    global _BOOTSTRAP_FETCHED
    with _CACHE_LOCK:
        if _BOOTSTRAP_FETCHED and not force_refresh:
            return dict(_BOOTSTRAP_MAP)

    resp = client.get(
        IANA_RDAP_DNS_BOOTSTRAP_URL,
        timeout=5.0,
        max_bytes=524288,
        retries=0,
        accept="application/json",
        bucket="data.iana.org",
    )
    parsed_map: Dict[str, str] = {}
    if resp.status == 200 and resp.body_text:
        try:
            parsed_map = _parse_iana_bootstrap(json.loads(resp.body_text))
        except Exception:
            parsed_map = {}

    with _CACHE_LOCK:
        _BOOTSTRAP_FETCHED = True
        if parsed_map:
            _BOOTSTRAP_MAP.clear()
            _BOOTSTRAP_MAP.update(parsed_map)
        return dict(_BOOTSTRAP_MAP)


def resolve_rdap_base_url(
    client: PoliteHttpClient,
    domain: str,
    use_bootstrap: bool = True,
) -> Optional[str]:
    """Resolve the authoritative RDAP base URL for a domain's TLD."""
    raw = (domain or "").strip().lower().rstrip(".")
    if not raw or _is_ip_literal(raw):
        return None
    reg = registrable_domain(raw)
    if not reg or "." not in reg or _is_ip_literal(reg):
        return None
    tld = reg.rsplit(".", 1)[-1].lower()

    if use_bootstrap:
        bmap = get_rdap_bootstrap(client)
        if tld in bmap:
            return bmap[tld]

    if tld in FALLBACK_RDAP_SERVERS:
        return FALLBACK_RDAP_SERVERS[tld]
    return None


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _extract_vcard_field(vcard_array: Any, field_name: str) -> Optional[str]:
    """Extract a text property (e.g. 'fn' or 'org') from an RFC 7095 jCard vcardArray."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    props = vcard_array[1]
    if not isinstance(props, list):
        return None
    target = field_name.lower()
    for prop in props:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        if str(prop[0]).lower() != target:
            continue
        val = prop[3]
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, list):
            parts = [str(x).strip() for x in val if isinstance(x, str) and x.strip()]
            if parts:
                return " ".join(parts)
    return None


def _extract_registrar(entities: Any) -> Optional[str]:
    """Recursively locate the entity with role 'registrar' and return its vCard fn/org/handle."""
    if not isinstance(entities, list):
        return None
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).strip().lower() for r in (ent.get("roles") or []) if r]
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            fn = _extract_vcard_field(vcard, "fn") or _extract_vcard_field(vcard, "org")
            if fn:
                return fn
            handle = ent.get("handle")
            if isinstance(handle, str) and handle.strip():
                return handle.strip()
        nested = ent.get("entities")
        if nested:
            found = _extract_registrar(nested)
            if found:
                return found
    return None


def parse_rdap_response(
    payload: Dict[str, Any],
    domain: str,
    rdap_url: str = "",
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Parse an RFC 9083 domain RDAP JSON object into a normalized passive profile."""
    ref_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reg = registrable_domain(domain) or domain.strip().lower()

    created_raw: Optional[str] = None
    updated_raw: Optional[str] = None
    expires_raw: Optional[str] = None
    created_dt: Optional[datetime] = None

    for ev in payload.get("events") or []:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction") or "").strip().lower()
        ev_date = str(ev.get("eventDate") or "").strip()
        if not ev_date:
            continue
        if action in ("registration", "registered"):
            dt = _parse_iso_datetime(ev_date)
            if created_dt is None or (dt is not None and dt < created_dt):
                created_dt = dt
                created_raw = ev_date
        elif action in ("last changed", "last update of rdap database"):
            if action == "last changed" or updated_raw is None:
                updated_raw = ev_date
        elif action == "expiration":
            expires_raw = ev_date

    age_days: Optional[int] = None
    if created_dt is not None:
        delta_s = (ref_now - created_dt).total_seconds()
        age_days = max(0, int(delta_s // 86400))

    registrar = _extract_registrar(payload.get("entities"))
    statuses = [str(s).strip() for s in (payload.get("status") or []) if isinstance(s, str) and s.strip()]

    return {
        "domain": reg,
        "ok": True,
        "error": None,
        "rdap_url": rdap_url,
        "created_at": created_raw,
        "updated_at": updated_raw,
        "expires_at": expires_raw,
        "age_days": age_days,
        "is_nod_30d": bool(age_days is not None and age_days < 30),
        "is_nod_90d": bool(age_days is not None and age_days < 90),
        "registrar": registrar,
        "status": statuses,
    }


def _failed_profile(domain: str, error: str, rdap_url: str = "") -> Dict[str, Any]:
    return {
        "domain": domain,
        "ok": False,
        "error": error,
        "rdap_url": rdap_url,
        "created_at": None,
        "updated_at": None,
        "expires_at": None,
        "age_days": None,
        "is_nod_30d": False,
        "is_nod_90d": False,
        "registrar": None,
        "status": [],
    }


def lookup_rdap(
    client: PoliteHttpClient,
    domain: str,
    use_bootstrap: bool = True,
    use_cache: bool = True,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Perform a 100% passive RFC 9083 HTTPS RDAP lookup for a registrable domain."""
    raw = (domain or "").strip().lower().rstrip(".")
    if not raw or _is_ip_literal(raw):
        return _failed_profile(raw or domain, "invalid_domain")
    reg = registrable_domain(raw)
    if not reg or "." not in reg or _is_ip_literal(reg):
        return _failed_profile(reg or domain, "invalid_domain")

    if use_cache:
        with _CACHE_LOCK:
            cached = _DOMAIN_CACHE.get(reg)
            if cached is not None:
                return dict(cached)

    base = resolve_rdap_base_url(client, reg, use_bootstrap=use_bootstrap)
    if not base:
        result = _failed_profile(reg, "unsupported_tld")
        if use_cache:
            with _CACHE_LOCK:
                _DOMAIN_CACHE[reg] = dict(result)
        return result

    query_url = f"{base}domain/{urllib.parse.quote(reg)}"
    bucket = urllib.parse.urlparse(query_url).netloc.lower() or "rdap"
    resp = client.get(
        query_url,
        timeout=5.5,
        max_bytes=262144,
        retries=0,
        accept="application/rdap+json, application/json",
        bucket=bucket,
        min_interval_override=0.35,
    )

    if resp.status != 200:
        err = f"http_{resp.status}" if resp.status else (resp.error or "network_error")
        result = _failed_profile(reg, err, rdap_url=query_url)
    else:
        try:
            payload = json.loads(resp.body_text)
            if not isinstance(payload, dict):
                result = _failed_profile(reg, "invalid_rdap_json", rdap_url=query_url)
            else:
                result = parse_rdap_response(payload, reg, rdap_url=query_url, now=now)
        except Exception as exc:
            result = _failed_profile(reg, f"json_error: {exc}", rdap_url=query_url)

    if use_cache:
        with _CACHE_LOCK:
            _DOMAIN_CACHE[reg] = dict(result)
    return result


def _collect_candidate_domains(
    v1_data: Dict[str, Any],
    v3_data: Dict[str, Any],
    max_domains: int,
    v2_data: Optional[Dict[str, Any]] = None,
) -> List[Tuple[str, List[str]]]:
    """Collect prioritized unique registrable domains from V3 lookalikes, spoofed badges, and V1 3P proxies."""
    ordered: Dict[str, List[str]] = {}

    def _add(raw_host_or_url: str, category: str) -> None:
        if not raw_host_or_url:
            return
        host = url_host(raw_host_or_url) if "://" in raw_host_or_url else raw_host_or_url.strip().lower()
        if not host or _is_ip_literal(host):
            return
        reg = registrable_domain(host)
        if not reg or "." not in reg or _is_ip_literal(reg):
            return
        cats = ordered.setdefault(reg, [])
        if category not in cats:
            cats.append(category)

    # Priority 1: V3 high-signal lookalikes (phishing, active agent endpoints, spoofed ANS badges)
    for item in v3_data.get("phishing_flagged") or []:
        if isinstance(item, dict) and item.get("domain"):
            _add(str(item["domain"]), "v3_phishing_lookalike")
    for item in v3_data.get("active_agent_endpoints") or []:
        if isinstance(item, dict) and item.get("domain"):
            _add(str(item["domain"]), "v3_active_lookalike_endpoint")
    for key in ("spoofed_ans_badge_hosts", "spoofed_ans_badges", "ans_badge_spoofing", "ans_badge_mismatches"):
        for item in v3_data.get(key) or []:
            if isinstance(item, dict):
                dom = item.get("domain") or item.get("host") or item.get("dialed_host")
                if dom:
                    _add(str(dom), "v3_spoofed_ans_badge")

    # Priority 1b: V2 spoofed `_ans-badge` hosts (e.g., direct audit of a lookalike domain)
    if isinstance(v2_data, dict):
        linter = v2_data.get("dns_aid_linter") or {}
        if isinstance(linter, dict):
            for item in linter.get("spoofed_ans_badge_hosts") or []:
                if isinstance(item, dict):
                    dom = item.get("host") or item.get("domain") or item.get("dialed_host")
                    if dom:
                        _add(str(dom), "v2_spoofed_ans_badge")
            for rec in linter.get("agent_records") or []:
                if not isinstance(rec, dict):
                    continue
                badge = rec.get("ans_badge") or {}
                if isinstance(badge, dict) and (badge.get("spoofed") or badge.get("host_binding_status") == "host_mismatch"):
                    dom = badge.get("host") or rec.get("target_host")
                    if dom:
                        _add(str(dom), "v2_spoofed_ans_badge")

    # Priority 2: V1 URL-path token exposed 3P proxies
    entries = ((v1_data.get("mcp_registry") or {}).get("entries") or [])
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("url_path_token_exposed"):
            for u in entry.get("token_exposed_urls") or []:
                _add(str(u), "v1_url_path_token_proxy")
            for d in entry.get("remote_domains") or []:
                _add(str(d), "v1_url_path_token_proxy")

    # Priority 3: V1 unverified 3P hosted proxies
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("classification") == "unverified_3p_hosted_proxy":
            for d in entry.get("remote_domains") or []:
                _add(str(d), "v1_unverified_3p_proxy")
            for r in entry.get("remotes") or []:
                if isinstance(r, dict) and r.get("url"):
                    _add(str(r["url"]), "v1_unverified_3p_proxy")

    items = list(ordered.items())
    return items[: max(0, max_domains)]


def enrich_report_rdap(
    client: PoliteHttpClient,
    v1_data: Dict[str, Any],
    v3_data: Dict[str, Any],
    max_domains: int = 15,
    use_bootstrap: bool = True,
    now: Optional[datetime] = None,
    v2_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Passively enrich V1 3P proxy domains and V3 lookalike domains with RFC 9083 RDAP age/registrar data.

    Returns a structured telemetry summary and annotates matching V3 hits in-place
    with compact RDAP metadata when resolved.
    """
    candidates = _collect_candidate_domains(v1_data, v3_data, max_domains=max_domains, v2_data=v2_data)
    profiles: Dict[str, Dict[str, Any]] = {}

    for dom, categories in candidates:
        prof = lookup_rdap(client, dom, use_bootstrap=use_bootstrap, now=now)
        prof["categories"] = list(categories)
        profiles[dom] = prof

    # Annotate V3 items non-destructively when RDAP profile exists
    for list_key in ("phishing_flagged", "active_agent_endpoints", "spoofed_ans_badge_hosts", "spoofed_ans_badges", "ans_badge_spoofing", "ans_badge_mismatches"):
        for item in v3_data.get(list_key) or []:
            if not isinstance(item, dict):
                continue
            raw_dom = item.get("domain") or item.get("host") or item.get("dialed_host")
            if not raw_dom:
                continue
            reg = registrable_domain(str(raw_dom))
            if reg in profiles:
                p = profiles[reg]
                item["rdap"] = {
                    "ok": p["ok"],
                    "age_days": p["age_days"],
                    "created_at": p["created_at"],
                    "registrar": p["registrar"],
                    "is_nod_30d": p["is_nod_30d"],
                    "is_nod_90d": p["is_nod_90d"],
                }

    # Annotate V2 spoofed `_ans-badge` hosts non-destructively when RDAP profile exists
    if isinstance(v2_data, dict):
        linter = v2_data.get("dns_aid_linter") or {}
        if isinstance(linter, dict):
            for item in linter.get("spoofed_ans_badge_hosts") or []:
                if not isinstance(item, dict):
                    continue
                raw_dom = item.get("host") or item.get("domain")
                if not raw_dom:
                    continue
                reg = registrable_domain(str(raw_dom))
                if reg in profiles:
                    p = profiles[reg]
                    item["rdap"] = {
                        "ok": p["ok"],
                        "age_days": p["age_days"],
                        "created_at": p["created_at"],
                        "registrar": p["registrar"],
                        "is_nod_30d": p["is_nod_30d"],
                        "is_nod_90d": p["is_nod_90d"],
                    }

    # Annotate V1 3P proxy entries non-destructively with remote domain RDAP ages
    for entry in (v1_data.get("mcp_registry") or {}).get("entries") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("classification") != "unverified_3p_hosted_proxy" and not entry.get("url_path_token_exposed"):
            continue
        doms: List[str] = []
        for d in entry.get("remote_domains") or []:
            r = registrable_domain(str(d))
            if r and r not in doms:
                doms.append(r)
        for rem in entry.get("remotes") or []:
            if isinstance(rem, dict) and rem.get("url"):
                r = registrable_domain(url_host(str(rem["url"])))
                if r and r not in doms:
                    doms.append(r)
        matched = {
            d: {
                "ok": profiles[d]["ok"],
                "age_days": profiles[d]["age_days"],
                "created_at": profiles[d]["created_at"],
                "registrar": profiles[d]["registrar"],
                "is_nod_30d": profiles[d]["is_nod_30d"],
                "is_nod_90d": profiles[d]["is_nod_90d"],
            }
            for d in doms
            if d in profiles
        }
        if matched:
            entry["remote_rdap"] = matched

    resolved = [p for p in profiles.values() if p.get("ok")]
    nod_30d = sorted(d for d, p in profiles.items() if p.get("is_nod_30d"))
    nod_90d = sorted(d for d, p in profiles.items() if p.get("is_nod_90d"))

    return {
        "enabled": True,
        "queried_count": len(profiles),
        "resolved_count": len(resolved),
        "nod_30d_count": len(nod_30d),
        "nod_90d_count": len(nod_90d),
        "nod_30d_domains": nod_30d,
        "nod_90d_domains": nod_90d,
        "domains": profiles,
    }
