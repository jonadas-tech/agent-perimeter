"""Vector 1 (Primary): MCP Ecosystem Supply-Chain & Brand Provenance Audit.

Correlates Official MCP Registry v0.1, npm, PyPI, and GitHub to separate:
  1. Officially domain-anchored first-party assets (reverse-DNS, verified GitHub orgs,
     verified sibling domains, and cross-registry maintainer email anchoring)
  2. Unverified 3rd-Party Hosted Proxies (with URL-Path Token Exposure detection)
  3. Unscoped Package / Free-Email Maintainer Collisions
  4. Official Registry Vacuum (0 official entries while unverified 3P claim the brand)

Uses strictly factual, neutral technical labels. 100% passive, read-only public APIs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse

from .dns_ct import host_matches_any, registrable_domain, url_host, url_matches_any
from .http_client import PoliteHttpClient
from .models import BrandTarget, Evidence, Finding
from .taxonomy import FINDING_DEFINITIONS, owasp_list_for

FREE_EMAIL_DOMAINS: Set[str] = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "qq.com",
    "163.com",
    "126.com",
    "yandex.ru",
    "mail.ru",
    "gmx.com",
    "fastmail.com",
}

NOREPLY_EMAIL_DOMAINS: Set[str] = {
    "users.noreply.github.com",
    "noreply.github.com",
    "users.noreply.gitlab.com",
    "noreply.gitlab.com",
}

HOSTING_PLATFORM_PREFIXES = (
    "io.github.",
    "io.gitlab.",
    "app.vercel.",
    "dev.workers.",
)

OFFICIAL_HOSTING_NAMESPACES: Set[str] = {
    "io.github.github",
    "com.github",
    "io.github.vercel",
    "com.vercel",
    "io.gitlab.gitlab",
    "com.gitlab",
    "io.github.cloudflare",
    "com.cloudflare",
}

# Built-in homonym exclusions to avoid false attributions on generic English / CS words
HOMONYM_EXCLUSIONS: Dict[str, Tuple[str, ...]] = {
    "snowflake": ("distributed-id", "snowflake-id", "id-generator", "twitter-snowflake"),
    "linear": ("linear-algebra", "linear-regression", "linear-programming", "linear-model", "collinear"),
    "slack": ("slackline", "slackware"),
    "shell": ("bash", "zsh", "powershell", "terminal", "command-line", "shell-exec", "shell-command", "subshell", "reverse-shell"),
    "meta": ("meta-mcp", "mcp-meta", "metadata", "metamask", "metaprompt", "metabase", "meta-agent", "meta-search", "meta-tool", "metacognitive"),
    "oracle": ("price-oracle", "chainlink", "pyth", "blockchain-oracle", "defi-oracle", "tarot", "divination", "i-ching"),
    "target": ("deployment-target", "build-target", "target-audience", "scan-target"),
    "delta": ("delta-lake", "deltalake", "delta-time", "git-delta", "delta-sync"),
    "visa": (
        "immigration", "passport", "travel-visa", "visa-check", "schengen",
        "visa-requirement", "visacalc", "visasubmit", "e-visa", "evisa",
        "work-visa", "student-visa", "tourist-visa", "visa-free", "visa-policy",
        "embassy", "consulate", "travel-document",
        "australian visa", "australian-visa", "uk visa", "us visa",
        "visa sponsor", "visa-sponsor", "visa processing", "visa-processing",
        "visa bulletin", "visa-bulletin", "green card", "h-1b", "h1b",
        "global talent", "talent-visa", "visamundi", "ternvisa",
        "visa application", "customs requirements", "subclass", "462 caps",
        "priority date", "endorser criteria",
    ),
    "fidelity": (
        "inference fidelity", "fidelity audit", "fidelity monitor",
        "conversation health", "high-fidelity", "high fidelity",
        "low-fidelity", "hi-fi", "hifi", "audio fidelity",
        "simulation fidelity", "drift, desync",
    ),
    "workday": (
        "business day", "business-day", "public holidays",
        "workday-calc", "workday-calendar", "days between dates",
        "bank holidays",
    ),
    "intercom": (
        "agent-intercom", "claude-intercom", "voice intercom",
        "message each other", "communication bridge between", "wakeable worker",
    ),
    "sentry": ("security linter", "static-analysis", "static analysis"),
    "cloudflare": ("senado-br", "brazilian senate"),
    "apple": ("pineapple", "apple-pie", "orchard"),
    "ford": ("stanford", "oxford", "bedford", "afford", "hartford"),
    "chase": ("purchase", "paperchase"),
    "block": ("blockchain", "adblock", "codeblock", "notion-block", "block-editor", "gutenberg", "blockscout", "blockstream"),
    "square": ("square-root", "squarespace", "foursquare", "times-square"),
    "uber": ("kubernetes", "ubersuggest"),
    "zoom": ("zoom-in", "image-zoom", "camera-zoom"),
    "intel": ("threat-intel", "osint", "intelligence", "market-intel", "sales-intel"),
    "sage": ("sagemaker", "sage-math", "sagemath"),
    "box": ("sandbox", "toolbox", "mailbox", "inbox", "checkbox", "blackbox", "mapbox", "virtualbox", "netbox", "outbox", "lightbox", "chatbox", "dropbox", "xbox"),
    "gap": ("rating-gap", "skill-gap", "gap-analysis", "air-gap"),
    "unity": ("community", "opportunity", "immunity"),
    "anthem": ("national-anthem",),
    "cvs": ("csv",),
}

# Known non-impersonating registry noise patterns (benchmarks, charts, synthetic observatory sensors, generic stack generators)
NOISE_SERVER_PREFIXES = (
    "com.modevc/",
    "io.github.sadri-dridi/",
    "ai.getvda/",
)

NOISE_REMOTE_HOST_SUBSTRINGS = (
    "agent-observatory-sensor.",
    "nolimit-observatory.workers.dev",
    "modevc.com/api/mcp/",
    ".getvda.ai/mcp",
)

NOISE_SLUG_RE = re.compile(
    r"(^|/)(chart-|arena-rating|.*-vs-.*|.*-url-shape$|.*-dsn-shape$|.*-observatory-sensor|.*-stack-generator|.*-compose-generator)",
    re.IGNORECASE,
)

# Platform-specific binary sub-packages on npm (avoid inflating collision counts)
PLATFORM_BINARY_SUFFIX_RE = re.compile(
    r"-(linux|darwin|win32|windows|freebsd|android)-(x64|arm64|ia32|amd64|386|arm|musl|gnu|msvc)$",
    re.IGNORECASE,
)

# Credential / token exposure in remote MCP URL path or query templates
URL_TOKEN_PATTERN_RE = re.compile(
    r"(\{(?:api[_-]?key|token|access[_-]?token|secret|auth[_-]?token|bearer|pat|key)\}"
    r"|[?&](?:api[_-]?key|token|access[_-]?token|secret|auth|key)=)",
    re.IGNORECASE,
)

MCP_INTENT_RE = re.compile(
    r"(?<![a-z0-9])(mcp|model[\s_-]*context[\s_-]*protocol|mcp-server|agent-toolkit|a2a)(?![a-z0-9])",
    re.IGNORECASE,
)

# Multi-provider generic aggregator slug detector (e.g., "openai-anthropic-google-cost-optimizer")
MULTI_VENDOR_TOKENS = {
    "openai", "anthropic", "google", "gemini", "claude", "langchain", "llamaindex",
    "mistral", "cohere", "bedrock", "vertex", "ollama",
}


def token_matches_aliases(text: str, aliases: List[str]) -> bool:
    if not text:
        return False
    low = text.lower()
    for alias in aliases:
        if len(alias) < 2:
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(alias.lower())}(?![a-z0-9])", low):
            return True
    return False


def _is_homonym_noise(text: str, target: BrandTarget) -> bool:
    low = text.lower()
    exclusions = list(target.exclude_terms)
    for a in target.normalized_aliases():
        exclusions.extend(HOMONYM_EXCLUSIONS.get(a, ()))
    for ex in exclusions:
        if ex.lower() in low:
            return True
    return False


def _is_multi_vendor_generic_slug(slug: str, aliases: List[str]) -> bool:
    """Filter generic multi-provider orchestration/benchmark slugs that mention 2+ other AI vendors."""
    parts = set(re.split(r"[^a-z0-9]+", slug.lower()))
    alias_set = {a.lower() for a in aliases}
    other_vendors = (parts & MULTI_VENDOR_TOKENS) - alias_set
    return len(other_vendors) >= 2


def reverse_dns_prefixes(verified_domains: List[str]) -> List[str]:
    prefixes: List[str] = []
    for dom in verified_domains:
        parts = [p for p in dom.lower().split(".") if p]
        if len(parts) < 2:
            continue
        rev = ".".join(reversed(parts))
        for suffix in ("/", "."):
            p = rev + suffix
            if p not in prefixes:
                prefixes.append(p)
        # Also handle well-known reverse-DNS root variants like com.datadog for datadoghq.com
        if parts[0].endswith("hq") and len(parts[0]) > 4:
            alt = ".".join(reversed([parts[0][:-2], *parts[1:]]))
            for suffix in ("/", "."):
                p = alt + suffix
                if p not in prefixes:
                    prefixes.append(p)
    return prefixes


def _matchable_registry_name(name: str) -> str:
    """Strip hosting-platform reverse-DNS prefixes so community servers hosted on GitHub/GitLab/
    Vercel/Cloudflare Workers do not falsely attribute to github.com, gitlab.com, vercel.com,
    or cloudflare.com, while preserving brand-owned GitHub org names (e.g. Snowflake-Labs/mcp).
    """
    low = name.lower()
    if low.startswith("dev.workers.") and "/" in name:
        return name.split("/", 1)[1]
    for prefix in ("io.github.", "io.gitlab.", "app.vercel."):
        if low.startswith(prefix):
            return name[len(prefix):]
    return name


def _is_security_holding_pkg(version: Any, description: str) -> bool:
    """Detect npm Security holding tombstones (e.g., 0.0.1-security / 'security holding package')."""
    ver_s = str(version or "").strip().lower()
    desc_s = (description or "").strip().lower()
    return ver_s.endswith("-security") or desc_s == "security holding package"


def _url_matches_official_site(url: str, verified_domains: List[str]) -> bool:
    """Match a website/blog URL against verified_domains while preventing third-party
    github.com/<random-user> or gitlab.com/<random-user> repo URLs from anchoring github.com/gitlab.com.
    """
    if not url or not url_matches_any(url, verified_domains):
        return False
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").strip().lower()
    if host in ("github.com", "www.github.com"):
        return path in ("", "/") or path == "/github" or path.startswith("/github/")
    if host in ("gitlab.com", "www.gitlab.com"):
        return (
            path in ("", "/")
            or path in ("/gitlab", "/gitlab-org")
            or path.startswith(("/gitlab/", "/gitlab-org/"))
        )
    return True


def _email_matches_domains(email: str, verified_domains: List[str]) -> bool:
    if not email or "@" not in email:
        return False
    # Extract email address from formats like "Name <user@domain.com>"
    m = re.search(r"([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})", email.lower())
    if not m:
        return False
    local_part, edom = m.group(1).split("@", 1)
    if edom in NOREPLY_EMAIL_DOMAINS:
        return False
    # npm OIDC / GitHub Actions publishes with noreply@github.com for ANY third-party repo
    if local_part in ("noreply", "no-reply") and edom in ("github.com", "gitlab.com"):
        return False
    return host_matches_any(edom, verified_domains)


def _extract_email_domain(email: str) -> Optional[str]:
    if not email or "@" not in email:
        return None
    m = re.search(r"@([a-z0-9.-]+\.[a-z]{2,})", email.lower())
    return m.group(1) if m else None


def _extract_free_email_domains(emails: List[str]) -> List[str]:
    found: Set[str] = set()
    for em in emails:
        dom = _extract_email_domain(em)
        if dom and dom in FREE_EMAIL_DOMAINS:
            found.add(dom)
    return sorted(found)


def _extract_github_owner(repo_url: str) -> str:
    if not repo_url:
        return ""
    m = re.search(r"github\.com[:/]([^/\s]+)/[^/\s]+", repo_url, re.IGNORECASE)
    return m.group(1) if m else ""


def _owner_matches_verified(owner: str, info: Dict[str, Any], verified_domains: List[str]) -> bool:
    """Evaluate whether a GitHub org/user is legitimately anchored to verified_domains."""
    owner_low = owner.lower()
    vset = {d.lower() for d in verified_domains}
    if "github.com" in vset:
        return owner_low == "github"
    if "gitlab.com" in vset:
        return owner_low in ("gitlab", "gitlab-org")
    return _url_matches_official_site(info.get("blog") or "", verified_domains) or _email_matches_domains(
        info.get("email") or "", verified_domains
    )


def _check_github_owner_anchored(
    client: PoliteHttpClient,
    owner: str,
    verified_domains: List[str],
    gh_cache: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Passively verify whether a GitHub organization/user is anchored to verified_domains."""
    key = owner.lower()
    with client._meta_lock:
        cached = gh_cache.get(key)
    if cached is not None:
        anchored = _owner_matches_verified(owner, cached, verified_domains)
        return {**cached, "domain_anchored": anchored}

    # Try /orgs/<owner> first (gives is_verified + org email + blog), fall back to /users/<owner>
    status, data, _ = client.github_api_json(f"orgs/{urllib.parse.quote(owner)}", is_search=False)
    if status != 200 or not isinstance(data, dict):
        status, data, _ = client.github_api_json(f"users/{urllib.parse.quote(owner)}", is_search=False)

    info: Dict[str, Any] = {
        "login": owner,
        "status": status,
        "type": None,
        "blog": None,
        "email": None,
        "is_verified": False,
    }
    if status == 200 and isinstance(data, dict):
        info["type"] = data.get("type") or "Organization"
        info["blog"] = data.get("blog") or ""
        info["email"] = data.get("email") or ""
        info["is_verified"] = bool(data.get("is_verified", False))

    with client._meta_lock:
        gh_cache[key] = info

    anchored = _owner_matches_verified(owner, info, verified_domains)
    return {**info, "domain_anchored": anchored}


def _fetch_npm_exact(
    client: PoliteHttpClient,
    pkg_name: str,
    verified_domains: List[str],
    gh_cache: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    encoded = urllib.parse.quote(pkg_name, safe="@")
    resp = client.get(f"https://registry.npmjs.org/{encoded}", timeout=7.0, retries=1)
    if resp.status != 200:
        return None
    try:
        data = json.loads(resp.body_text)
    except Exception:
        return None
    latest_ver = (data.get("dist-tags") or {}).get("latest")
    time_map = data.get("time") or {}
    versions_map = data.get("versions") or {}
    # F4: Skip unpublished npm tombstones (no dist-tags.latest, unpublished timestamp, or empty versions)
    if not latest_ver or "unpublished" in time_map or not versions_map:
        return None
    desc = str(data.get("description") or "")
    is_sec_holding = _is_security_holding_pkg(latest_ver, desc)
    maintainers = data.get("maintainers") or []
    m_emails = [m.get("email", "") for m in maintainers if isinstance(m, dict) and m.get("email")]
    homepage = data.get("homepage", "") or ""
    repo = data.get("repository")
    repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo or "")
    email_anchored = any(_email_matches_domains(em, verified_domains) for em in m_emails)
    site_anchored = _url_matches_official_site(homepage, verified_domains)
    gh_owner = _extract_github_owner(repo_url)
    gh_anchored = False
    if gh_owner and not email_anchored:
        gh_info = _check_github_owner_anchored(client, gh_owner, verified_domains, gh_cache)
        gh_anchored = bool(gh_info.get("domain_anchored"))
    # F3: Never anchor npm official status on self-asserted homepage alone; require verified email or GitHub org
    official_anchored = (not is_sec_holding) and (email_anchored or gh_anchored)
    free_email_domains = _extract_free_email_domains(m_emails)
    free_email = (not official_anchored) and (not is_sec_holding) and bool(free_email_domains)
    first_edom = _extract_email_domain(m_emails[0]) if m_emails else None
    return {
        "name": pkg_name,
        "version": latest_ver,
        "description": desc[:200],
        "downloads_monthly": None,
        "publisher_username": (
            maintainers[0].get("name") if maintainers and isinstance(maintainers[0], dict) else None
        ),
        "publisher_email_domain": first_edom,
        "free_email_domains": free_email_domains,
        "maintainer_count": len(maintainers),
        "npm_url": f"https://www.npmjs.com/package/{pkg_name}",
        "repository_url": repo_url,
        "homepage": homepage,
        "official_anchored": official_anchored,
        "is_security_holding": is_sec_holding,
        "anchoring_signals": {
            "maintainer_email": email_anchored,
            "homepage_domain": site_anchored,
            "github_org": gh_anchored,
        },
        "free_email_maintainer": free_email,
        "is_scoped": pkg_name.startswith("@"),
        "source": "npm_exact_probe",
    }


def probe_vector1(
    client: PoliteHttpClient,
    target: BrandTarget,
    verified_domains: List[str],
    gh_cache: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Any], List[Finding]]:
    """Run Vector 1 supply-chain provenance audit across MCP Registry, npm, PyPI, and GitHub."""
    brand = target.brand.lower()
    aliases = target.normalized_aliases()
    rev_prefixes = reverse_dns_prefixes(verified_domains)

    # ------------------------------------------------------------------
    # 1A. Official MCP Registry v0.1 (broad search + targeted official-anchor queries)
    # ------------------------------------------------------------------
    raw_mcp_entries: List[Dict[str, Any]] = []
    mcp_errors: List[str] = []
    seen_server_keys: Set[str] = set()

    def _ingest_mcp_page(qs: str, tag: str) -> Optional[str]:
        resp = client.get(f"https://registry.modelcontextprotocol.io/v0.1/servers?{qs}", timeout=8.0, retries=1)
        if resp.status != 200:
            mcp_errors.append(f"{tag}: http_{resp.status} {resp.error or ''}".strip())
            return None
        try:
            payload = json.loads(resp.body_text)
        except Exception as e:
            mcp_errors.append(f"{tag}: json_error {e}")
            return None
        for item in payload.get("servers", []) or []:
            srv = item.get("server", {}) or {}
            meta = (item.get("_meta", {}) or {}).get("io.modelcontextprotocol.registry/official", {}) or {}
            name = str(srv.get("name") or "")
            ver = str(srv.get("version") or "")
            dedup_key = f"{name}@{ver}"
            if not name or dedup_key in seen_server_keys:
                continue
            seen_server_keys.add(dedup_key)
            raw_mcp_entries.append({"srv": srv, "meta": meta})
        return (payload.get("metadata") or {}).get("nextCursor")

    cursor: Optional[str] = None
    for page in range(2):
        qs = f"search={urllib.parse.quote(brand)}&limit=100"
        if cursor:
            qs += f"&cursor={urllib.parse.quote(cursor)}"
        cursor = _ingest_mcp_page(qs, f"page_{page}")
        if not cursor:
            break

    # F2: Issue targeted reverse-DNS + io.github.<brand> queries so high-volume community
    # namespaces (e.g. io.github.0* for github.com) can never push official entries past page 2.
    targeted_queries: List[str] = []
    for rp in rev_prefixes:
        root_q = rp.rstrip("/.")
        if root_q and root_q not in targeted_queries:
            targeted_queries.append(root_q)
        if len(targeted_queries) >= 3:
            break
    gh_ns_q = f"io.github.{brand}"
    if gh_ns_q not in targeted_queries:
        targeted_queries.append(gh_ns_q)
    for tq in targeted_queries:
        _ingest_mcp_page(f"search={urllib.parse.quote(tq)}&limit=25", f"anchor_{tq}")

    # Deduplicate to latest version per server name before expensive cross-checks
    latest_by_name: Dict[str, Dict[str, Any]] = {}
    for row in raw_mcp_entries:
        n = str(row["srv"].get("name") or "")
        if n not in latest_by_name or row["meta"].get("isLatest"):
            latest_by_name[n] = row

    # ------------------------------------------------------------------
    # 1B. npm Registry search + exact high-risk candidate names
    # ------------------------------------------------------------------
    npm_packages: Dict[str, Dict[str, Any]] = {}
    npm_errors: List[str] = []
    search_resp = client.get(
        f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(brand + ' mcp')}&size=25",
        timeout=10.0,
        retries=1,
    )
    if search_resp.status == 200:
        try:
            objs = json.loads(search_resp.body_text).get("objects", []) or []
            for obj in objs:
                pkg = obj.get("package", {}) or {}
                pname = str(pkg.get("name") or "")
                if not pname or PLATFORM_BINARY_SUFFIX_RE.search(pname):
                    continue
                pdesc = str(pkg.get("description") or "")
                pkeywords = " ".join(str(k) for k in (pkg.get("keywords") or []))
                # STRICT NAME RELEVANCE: brand alias MUST appear in package name (eliminates `ai` 194M dl FP)
                name_norm = pname.replace("/", " ").replace("-", " ").replace("_", " ").replace("@", " ")
                if not token_matches_aliases(name_norm, aliases):
                    continue
                if not MCP_INTENT_RE.search(f"{pname} {pdesc} {pkeywords}"):
                    continue
                if _is_homonym_noise(f"{pname} {pdesc}", target):
                    continue
                if _is_multi_vendor_generic_slug(pname, aliases):
                    continue

                pub = pkg.get("publisher") or {}
                pub_email = str(pub.get("email") or "")
                maintainers = pkg.get("maintainers") or []
                m_emails = [str(m.get("email") or "") for m in maintainers if isinstance(m, dict) and m.get("email")]
                all_emails = [e for e in [pub_email, *m_emails] if e]
                links = pkg.get("links") or {}
                repo_link = str(links.get("repository") or "")
                homepage = str(links.get("homepage") or "")
                pkg_ver = pkg.get("version")
                if not pkg_ver:
                    continue
                is_sec_holding = _is_security_holding_pkg(pkg_ver, pdesc)

                email_anchored = any(_email_matches_domains(em, verified_domains) for em in all_emails)
                site_anchored = _url_matches_official_site(homepage, verified_domains)
                gh_owner = _extract_github_owner(repo_link)
                gh_anchored = False
                if gh_owner and not email_anchored:
                    gh_info = _check_github_owner_anchored(client, gh_owner, verified_domains, gh_cache)
                    gh_anchored = bool(gh_info.get("domain_anchored"))
                # F3: Never anchor npm official status on self-asserted homepage alone
                official_flag = (not is_sec_holding) and (email_anchored or gh_anchored)
                free_email_domains = _extract_free_email_domains(all_emails)
                free_email = (not official_flag) and (not is_sec_holding) and bool(free_email_domains)
                npm_packages[pname] = {
                    "name": pname,
                    "version": pkg_ver,
                    "description": pdesc[:200],
                    "downloads_monthly": (obj.get("downloads") or {}).get("monthly"),
                    "publisher_username": pub.get("username"),
                    "publisher_email_domain": _extract_email_domain(pub_email) or (
                        _extract_email_domain(m_emails[0]) if m_emails else None
                    ),
                    "free_email_domains": free_email_domains,
                    "maintainer_count": len(maintainers),
                    "npm_url": links.get("npm") or f"https://www.npmjs.com/package/{pname}",
                    "repository_url": repo_link,
                    "homepage": homepage,
                    "official_anchored": official_flag,
                    "is_security_holding": is_sec_holding,
                    "anchoring_signals": {
                        "maintainer_email": email_anchored,
                        "homepage_domain": site_anchored,
                        "github_org": gh_anchored,
                    },
                    "free_email_maintainer": free_email,
                    "is_scoped": pname.startswith("@"),
                    "source": "npm_search",
                }
        except Exception as e:
            npm_errors.append(f"search_json_error: {e}")
    else:
        npm_errors.append(f"search_http_{search_resp.status}: {search_resp.error or ''}".strip())

    # Exact high-risk npm collision candidates
    npm_candidates = [
        f"@{brand}/mcp",
        f"@{brand}/mcp-server",
        f"{brand}-mcp",
        f"mcp-{brand}",
        f"mcp-server-{brand}",
        f"{brand}-mcp-server",
    ]
    for cand in npm_candidates:
        if cand in npm_packages:
            continue
        exact_pkg = _fetch_npm_exact(client, cand, verified_domains, gh_cache)
        if exact_pkg:
            if not _is_homonym_noise(f"{exact_pkg['name']} {exact_pkg['description']}", target):
                npm_packages[cand] = exact_pkg

    # ------------------------------------------------------------------
    # Classify Official MCP Registry Entries (with Cross-Registry Anchoring)
    # ------------------------------------------------------------------
    mcp_entries: List[Dict[str, Any]] = []
    noise_filtered_count = 0
    for name, row in sorted(latest_by_name.items()):
        srv = row["srv"]
        meta = row["meta"]
        title = str(srv.get("title") or "")
        desc = str(srv.get("description") or "")
        website = str(srv.get("websiteUrl") or "")
        repo_url = str((srv.get("repository") or {}).get("url") or "")
        remotes = [r for r in (srv.get("remotes") or []) if isinstance(r, dict) and r.get("url")]
        packages = [p for p in (srv.get("packages") or []) if isinstance(p, dict)]

        # F1: Strip hosting-platform reverse-DNS prefixes (io.github.<user>/, app.vercel.<app>/, dev.workers.*)
        # before matching brand aliases so community servers hosted on GitHub/Vercel/Workers do not leak.
        matchable_name = _matchable_registry_name(name)
        name_norm = matchable_name.replace("/", " ").replace("-", " ").replace("_", " ").replace(".", " ")
        name_matches = token_matches_aliases(name_norm, aliases)
        title_matches = token_matches_aliases(title, aliases)
        site_anchored = _url_matches_official_site(website, verified_domains)
        if not (name_matches or title_matches or site_anchored):
            continue

        # Filter obvious non-impersonating noise (benchmarks, synthetic sensors, homonyms)
        remote_urls = [str(r.get("url") or "") for r in remotes]
        if (
            any(name.lower().startswith(p) for p in NOISE_SERVER_PREFIXES)
            or NOISE_SLUG_RE.search(name)
            or any(any(ns in ru.lower() for ns in NOISE_REMOTE_HOST_SUBSTRINGS) for ru in remote_urls)
            or _is_homonym_noise(f"{name} {title} {desc}", target)
            or _is_multi_vendor_generic_slug(name, aliases)
        ):
            noise_filtered_count += 1
            continue

        # Anchoring signals
        rev_anchored = any(name.lower().startswith(p) for p in rev_prefixes)
        all_remotes_brand_hosted = bool(remote_urls) and all(
            url_matches_any(u, verified_domains) for u in remote_urls
        )
        has_third_party_remote = any(
            u and not url_matches_any(u, verified_domains) for u in remote_urls
        )

        # GitHub org check (check ALL repo owners whose repo is in MCP Registry!)
        gh_owner = _extract_github_owner(repo_url)
        gh_anchored = False
        if gh_owner:
            gh_info = _check_github_owner_anchored(client, gh_owner, verified_domains, gh_cache)
            gh_anchored = bool(gh_info.get("domain_anchored"))

        # Cross-registry package anchoring (e.g., io.github.mongodb-js/mongodb-mcp-server -> npm @mongodb.com)
        pkg_anchored = False
        for p in packages:
            rtype = str(p.get("registryType") or "").lower()
            ident = str(p.get("identifier") or "").strip()
            if rtype == "npm" and ident:
                existing = npm_packages.get(ident)
                if existing is None:
                    existing = _fetch_npm_exact(client, ident, verified_domains, gh_cache)
                    if existing:
                        ident_norm = ident.replace("/", " ").replace("-", " ").replace("_", " ").replace("@", " ")
                        if token_matches_aliases(ident_norm, aliases) and not _is_homonym_noise(
                            f"{ident} {existing.get('description', '')}", target
                        ):
                            npm_packages[ident] = existing
                if existing and existing.get("official_anchored"):
                    pkg_anchored = True
                    break

        # Website anchor alone does NOT override a third-party hosted remote URL
        effective_site_anchor = site_anchored and not has_third_party_remote
        is_official = rev_anchored or all_remotes_brand_hosted or gh_anchored or pkg_anchored or effective_site_anchor

        # Inspect remote URLs for URL-path/query token templates
        token_exposed_urls = [u for u in remote_urls if URL_TOKEN_PATTERN_RE.search(u)]
        remote_hosts = sorted({url_host(u) for u in remote_urls if url_host(u)})
        remote_registrable_domains = sorted({registrable_domain(h) for h in remote_hosts if h})

        if is_official:
            classification = "official_domain_anchored"
        elif has_third_party_remote:
            classification = "unverified_3p_hosted_proxy"
        else:
            classification = "unverified_3p_package_entry"

        mcp_entries.append(
            {
                "name": name,
                "title": title,
                "version": str(srv.get("version") or ""),
                "description": desc[:220],
                "websiteUrl": website,
                "repositoryUrl": repo_url,
                "remotes": [{"type": r.get("type"), "url": r.get("url")} for r in remotes],
                "remote_domains": remote_registrable_domains,
                "url_path_token_exposed": bool(token_exposed_urls),
                "token_exposed_urls": token_exposed_urls,
                "packages": [
                    {
                        "registryType": p.get("registryType"),
                        "identifier": p.get("identifier"),
                        "version": p.get("version"),
                    }
                    for p in packages
                ],
                "status": meta.get("status"),
                "publishedAt": meta.get("publishedAt"),
                "classification": classification,
                "anchoring_signals": {
                    "reverse_dns_prefix": rev_anchored,
                    "first_party_remote_domain": all_remotes_brand_hosted,
                    "github_org_verified": gh_anchored,
                    "package_maintainer_email": pkg_anchored,
                    "website_domain": effective_site_anchor,
                },
            }
        )

    # ------------------------------------------------------------------
    # 1C. PyPI JSON API checks (deterministic collision names + registry refs)
    # ------------------------------------------------------------------
    pypi_candidates: List[str] = [
        f"{brand}-mcp",
        f"mcp-{brand}",
        f"mcp-server-{brand}",
        f"{brand}-mcp-server",
        f"{brand}-agent-toolkit",
    ]
    for e in mcp_entries:
        for p in e.get("packages", []):
            if str(p.get("registryType") or "").lower() == "pypi" and p.get("identifier"):
                pid = str(p["identifier"]).strip()
                if pid not in pypi_candidates:
                    pypi_candidates.append(pid)

    pypi_packages: List[Dict[str, Any]] = []
    for cand in pypi_candidates:
        r = client.get(f"https://pypi.org/pypi/{urllib.parse.quote(cand)}/json", timeout=7.0, retries=0)
        if r.status != 200:
            continue
        try:
            info = json.loads(r.body_text).get("info") or {}
        except Exception:
            continue
        summary = str(info.get("summary") or "")
        if _is_homonym_noise(f"{cand} {summary}", target):
            continue
        proj_urls = info.get("project_urls") or {}
        home_page = str(info.get("home_page") or "")
        author_email = str(info.get("author_email") or "")
        maintainer_email = str(info.get("maintainer_email") or "")
        all_urls = [home_page] + [str(v) for v in proj_urls.values() if v]
        all_emails = [em for em in (author_email, maintainer_email) if em]
        site_anchored = any(_url_matches_official_site(u, verified_domains) for u in all_urls)
        email_anchored = any(
            _email_matches_domains(em, verified_domains) for em in all_emails
        )
        gh_anchored = False
        if not email_anchored:
            for u in all_urls:
                gh_owner = _extract_github_owner(u)
                if gh_owner:
                    gh_info = _check_github_owner_anchored(client, gh_owner, verified_domains, gh_cache)
                    if gh_info.get("domain_anchored"):
                        gh_anchored = True
                        break
        # F3: Never anchor PyPI official status on self-asserted homepage/project_urls alone
        official_flag = email_anchored or gh_anchored
        free_email_domains = _extract_free_email_domains(all_emails)
        free_email = (not official_flag) and bool(free_email_domains)
        pypi_packages.append(
            {
                "name": info.get("name") or cand,
                "version": info.get("version"),
                "summary": summary[:200],
                "author": info.get("author"),
                "author_email_domain": _extract_email_domain(author_email) or _extract_email_domain(maintainer_email),
                "free_email_domains": free_email_domains,
                "home_page": home_page,
                "pypi_url": info.get("package_url") or f"https://pypi.org/project/{cand}/",
                "official_anchored": official_flag,
                "anchoring_signals": {
                    "maintainer_email": email_anchored,
                    "homepage_domain": site_anchored,
                    "github_org": gh_anchored,
                },
                "free_email_maintainer": free_email,
            }
        )

    # ------------------------------------------------------------------
    # 1D. GitHub Top Repositories (contextual provenance signal)
    # ------------------------------------------------------------------
    gh_repos: List[Dict[str, Any]] = []
    gh_error: Optional[str] = None
    q = urllib.parse.quote(f"{brand} mcp in:name,description")
    gh_status, gh_data, gh_err = client.github_api_json(
        f"search/repositories?q={q}&sort=stars&order=desc&per_page=8",
        is_search=True,
    )
    if gh_status == 200 and isinstance(gh_data, dict):
        for item in gh_data.get("items", []) or []:
            full_name = str(item.get("full_name") or "")
            desc = str(item.get("description") or "")
            if _is_homonym_noise(f"{full_name} {desc}", target):
                continue
            if not token_matches_aliases(full_name.replace("/", " ").replace("-", " ").replace("_", " "), aliases):
                continue
            owner = item.get("owner") or {}
            owner_login = str(owner.get("login") or "")
            homepage = str(item.get("homepage") or "")
            anchored = _url_matches_official_site(homepage, verified_domains)
            if not anchored and owner_login:
                gh_info = _check_github_owner_anchored(client, owner_login, verified_domains, gh_cache)
                anchored = bool(gh_info.get("domain_anchored"))
            gh_repos.append(
                {
                    "full_name": full_name,
                    "html_url": item.get("html_url"),
                    "stars": item.get("stargazers_count"),
                    "owner_login": owner_login,
                    "description": desc[:200],
                    "homepage": homepage,
                    "official_anchored": anchored,
                }
            )
    else:
        gh_error = gh_err or f"http_{gh_status}"

    # ------------------------------------------------------------------
    # Aggregate & Generate Findings with Verifiable Raw Evidence
    # ------------------------------------------------------------------
    official_mcp = [e for e in mcp_entries if e["classification"] == "official_domain_anchored"]
    hosted_3p_proxies = [e for e in mcp_entries if e["classification"] == "unverified_3p_hosted_proxy"]
    token_exposed_proxies = [e for e in hosted_3p_proxies if e.get("url_path_token_exposed")]
    unverified_registry_pkg_entries = [
        e for e in mcp_entries if e["classification"] == "unverified_3p_package_entry"
    ]

    npm_all = sorted(npm_packages.values(), key=lambda x: x.get("downloads_monthly") or 0, reverse=True)
    # F5: Separate npm Security holding tombstones (0.0.1-security) out of active collisions
    npm_security_holding = [p for p in npm_all if p.get("is_security_holding")]
    npm_list = [p for p in npm_all if not p.get("is_security_holding")]
    npm_official = [p for p in npm_list if p.get("official_anchored")]
    npm_unverified = [p for p in npm_list if not p.get("official_anchored")]
    npm_free_email = [p for p in npm_unverified if p.get("free_email_maintainer")]
    npm_unscoped_collisions = [
        p for p in npm_unverified if (not p.get("is_scoped") or (p.get("downloads_monthly") or 0) >= 1000)
    ]

    pypi_official = [p for p in pypi_packages if p.get("official_anchored")]
    pypi_unverified = [p for p in pypi_packages if not p.get("official_anchored")]
    pypi_free_email = [p for p in pypi_unverified if p.get("free_email_maintainer")]

    has_any_3p_brand_claim = bool(hosted_3p_proxies or unverified_registry_pkg_entries or npm_unverified or pypi_unverified)
    official_registry_vacuum = (len(official_mcp) == 0) and has_any_3p_brand_claim

    findings: List[Finding] = []

    # Finding 1A: URL-Path Token Exposure (Critical)
    if token_exposed_proxies:
        defn = FINDING_DEFINITIONS["v1_url_path_token_exposure"]
        evs = [
            Evidence(
                source="mcp_registry",
                locator=f"https://registry.modelcontextprotocol.io/v0.1/servers?search={urllib.parse.quote(brand)}",
                detail=f"{e['name']} -> {', '.join(e['token_exposed_urls'])}",
                raw={
                    "server_name": e["name"],
                    "version": e["version"],
                    "token_exposed_urls": e["token_exposed_urls"],
                    "repositoryUrl": e["repositoryUrl"],
                },
            )
            for e in token_exposed_proxies[:8]
        ]
        findings.append(
            Finding(
                rule_id="v1_url_path_token_exposure",
                vector="V1",
                label=str(defn["label"]),
                severity="critical",
                title=(
                    f"{len(token_exposed_proxies)} unverified 3rd-party MCP proxy(ies) embed "
                    f"credential/token templates in remote URLs"
                ),
                summary=(
                    f"Official MCP Registry entries claiming '{target.brand}' expose remote endpoint templates "
                    f"that place bearer tokens or API keys directly inside URL paths/query parameters on "
                    f"non-brand hosts, increasing credential logging and intermediation risk."
                ),
                owasp=owasp_list_for("v1_url_path_token_exposure"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 1B: Unverified 3rd-Party Hosted Proxies (High)
    if hosted_3p_proxies:
        defn = FINDING_DEFINITIONS["v1_unverified_3p_hosted_proxy"]
        unique_hosts = sorted({d for e in hosted_3p_proxies for d in e.get("remote_domains", [])})
        evs = [
            Evidence(
                source="mcp_registry",
                locator=e["remotes"][0]["url"] if e.get("remotes") else e["name"],
                detail=(
                    f"Registry entry `{e['name']}` ({e['version']}) routes to third-party remote "
                    f"`{e['remotes'][0]['url']}`"
                ),
                raw={
                    "server_name": e["name"],
                    "version": e["version"],
                    "remotes": e["remotes"],
                    "repositoryUrl": e["repositoryUrl"],
                },
            )
            for e in hosted_3p_proxies[:10]
        ]
        findings.append(
            Finding(
                rule_id="v1_unverified_3p_hosted_proxy",
                vector="V1",
                label=str(defn["label"]),
                severity="high",
                title=(
                    f"{len(hosted_3p_proxies)} unverified 3rd-party hosted MCP proxy(ies) across "
                    f"{len(unique_hosts)} external domain(s)"
                ),
                summary=(
                    f"Third-party hosted remote MCP servers listed in the Official MCP Registry matching "
                    f"'{target.brand}' declare external remote endpoint domains ({', '.join(unique_hosts[:5])}) "
                    f"not domain-anchored to {target.domain}, introducing unverified third-party intermediation "
                    f"boundaries if adopted by users or agents."
                ),
                owasp=owasp_list_for("v1_unverified_3p_hosted_proxy"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 1C: Official Registry Vacuum (High)
    if official_registry_vacuum:
        defn = FINDING_DEFINITIONS["v1_official_registry_vacuum"]
        evs = [
            Evidence(
                source="mcp_registry",
                locator=f"https://registry.modelcontextprotocol.io/v0.1/servers?search={urllib.parse.quote(brand)}",
                detail=(
                    f"0 officially domain-anchored MCP Registry entries for {target.domain}; "
                    f"{len(hosted_3p_proxies) + len(unverified_registry_pkg_entries)} unverified registry entries, "
                    f"{len(npm_unverified)} unverified npm packages, {len(pypi_unverified)} unverified PyPI packages."
                ),
                raw={
                    "verified_domains_checked": verified_domains,
                    "official_registry_count": 0,
                    "unverified_registry_count": len(hosted_3p_proxies) + len(unverified_registry_pkg_entries),
                    "unverified_npm_count": len(npm_unverified),
                    "unverified_pypi_count": len(pypi_unverified),
                },
            )
        ]
        findings.append(
            Finding(
                rule_id="v1_official_registry_vacuum",
                vector="V1",
                label=str(defn["label"]),
                severity="high",
                title=f"Zero officially domain-anchored entries in Official MCP Registry for {target.domain}",
                summary=(
                    f"No reverse-DNS or domain-verified entry for {target.domain} exists in the Official MCP "
                    f"Registry, while unverified third-party servers/packages already claim '{target.brand}'."
                ),
                owasp=owasp_list_for("v1_official_registry_vacuum"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 1D: Unverified Package / Free-Email Maintainer (High)
    free_email_total = len(npm_free_email) + len(pypi_free_email)
    if free_email_total > 0:
        defn = FINDING_DEFINITIONS["v1_unscoped_free_email_collision"]
        evs: List[Evidence] = []
        for p in npm_free_email[:8]:
            dl = f", {p['downloads_monthly']:,} dl/mo" if p.get("downloads_monthly") else ""
            pub_dom = p.get("publisher_email_domain")
            free_doms = p.get("free_email_domains") or []
            extra_free = [d for d in free_doms if d != pub_dom]
            if pub_dom and extra_free:
                email_desc = f"publisher: {pub_dom}, co-maintainer: {', '.join(extra_free[:2])}"
            else:
                email_desc = f"maintainer email domain: {pub_dom or (', '.join(free_doms[:2]) if free_doms else 'unknown')}"
            evs.append(
                Evidence(
                    source="npm",
                    locator=p["npm_url"],
                    detail=f"npm `{p['name']}` v{p.get('version')} ({email_desc}{dl})",
                    raw=p,
                )
            )
        for p in pypi_free_email[:5]:
            pub_dom = p.get("author_email_domain")
            free_doms = p.get("free_email_domains") or []
            extra_free = [d for d in free_doms if d != pub_dom]
            if pub_dom and extra_free:
                email_desc = f"author: {pub_dom}, co-maintainer: {', '.join(extra_free[:2])}"
            else:
                email_desc = f"maintainer email domain: {pub_dom or (', '.join(free_doms[:2]) if free_doms else 'unknown')}"
            evs.append(
                Evidence(
                    source="pypi",
                    locator=p["pypi_url"],
                    detail=f"PyPI `{p['name']}` v{p.get('version')} ({email_desc})",
                    raw=p,
                )
            )
        findings.append(
            Finding(
                rule_id="v1_unscoped_free_email_collision",
                vector="V1",
                label=str(defn["label"]),
                severity="high",
                title=(
                    f"{free_email_total} unverified brand-named MCP package(s) published by free-email maintainers"
                ),
                summary=(
                    f"Unverified npm/PyPI MCP packages matching '{target.brand}' are maintained via consumer "
                    f"free-email accounts (e.g., gmail.com / protonmail.com) without corporate domain provenance, "
                    f"creating install-ambiguity and account-takeover supply-chain risk for coding agents."
                ),
                owasp=owasp_list_for("v1_unscoped_free_email_collision"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    # Finding 1E: Unverified Package Namespace Collision (Medium, when non-free-email unscoped/high-dl collisions exist)
    remaining_collisions = [
        p for p in npm_unscoped_collisions if not p.get("free_email_maintainer")
    ]
    remaining_pypi = [p for p in pypi_unverified if not p.get("free_email_maintainer")]
    if remaining_collisions or remaining_pypi:
        defn = FINDING_DEFINITIONS["v1_unverified_package_collision"]
        evs = []
        for p in remaining_collisions[:6]:
            dl = f"{p['downloads_monthly']:,} dl/mo" if p.get("downloads_monthly") else "exact unscoped name"
            evs.append(
                Evidence(
                    source="npm",
                    locator=p["npm_url"],
                    detail=f"npm `{p['name']}` ({dl}; email domain: {p.get('publisher_email_domain') or 'none'})",
                    raw=p,
                )
            )
        for p in remaining_pypi[:4]:
            evs.append(
                Evidence(
                    source="pypi",
                    locator=p["pypi_url"],
                    detail=f"PyPI `{p['name']}` v{p.get('version')} (unverified provenance)",
                    raw=p,
                )
            )
        findings.append(
            Finding(
                rule_id="v1_unverified_package_collision",
                vector="V1",
                label=str(defn["label"]),
                severity="medium",
                title=(
                    f"{len(remaining_collisions) + len(remaining_pypi)} unverified unscoped/high-traffic "
                    f"MCP package(s) claiming '{target.brand}'"
                ),
                summary=(
                    f"Public npm/PyPI packages use canonical brand-named MCP identifiers without domain-verified "
                    f"provenance to {target.domain}, increasing agent installation ambiguity."
                ),
                owasp=owasp_list_for("v1_unverified_package_collision"),
                evidence=evs,
                recommendation=str(defn["recommendation"]),
            )
        )

    v1_data: Dict[str, Any] = {
        "mcp_registry": {
            "total_relevant": len(mcp_entries),
            "noise_filtered_count": noise_filtered_count,
            "official_count": len(official_mcp),
            "unverified_3p_hosted_proxy_count": len(hosted_3p_proxies),
            "url_path_token_exposed_count": len(token_exposed_proxies),
            "unverified_3p_package_entry_count": len(unverified_registry_pkg_entries),
            "entries": mcp_entries,
            "errors": mcp_errors,
        },
        "npm": {
            "total_relevant": len(npm_list),
            "official_count": len(npm_official),
            "unverified_count": len(npm_unverified),
            "free_email_unverified_count": len(npm_free_email),
            "security_holding_count": len(npm_security_holding),
            "security_holding_packages": npm_security_holding,
            "packages": npm_list,
            "errors": npm_errors,
        },
        "pypi": {
            "found_count": len(pypi_packages),
            "official_count": len(pypi_official),
            "unverified_count": len(pypi_unverified),
            "free_email_unverified_count": len(pypi_free_email),
            "packages": pypi_packages,
        },
        "github": {
            "repo_count": len(gh_repos),
            "official_count": sum(1 for r in gh_repos if r.get("official_anchored")),
            "top_repo_is_third_party": bool(gh_repos and not gh_repos[0].get("official_anchored")),
            "repos": gh_repos,
            "error": gh_error,
        },
        "flags": {
            "has_official_mcp_registry_entry": len(official_mcp) > 0,
            "official_registry_vacuum": official_registry_vacuum,
            "has_unverified_3p_hosted_proxy": len(hosted_3p_proxies) > 0,
            "has_url_path_token_exposure": len(token_exposed_proxies) > 0,
            "has_unscoped_free_email_collision": free_email_total > 0,
            "has_unverified_package_collision": len(npm_unverified) > 0 or len(pypi_unverified) > 0,
            "has_any_mcp_footprint": bool(official_mcp or has_any_3p_brand_claim),
        },
    }
    return v1_data, findings
