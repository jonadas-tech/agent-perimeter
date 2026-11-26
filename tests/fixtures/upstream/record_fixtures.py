"""Re-record upstream API fixtures used by tests/test_upstream_contracts.py.

Run manually (needs network, stdlib only):

    python tests/fixtures/upstream/record_fixtures.py

Targets are neutral on purpose: the tool's own PyPI/MCP Registry entries, the official
MCP SDK org on npm, the maintainer's GitHub account, and the IANA documentation domain
example.com for DNS. No study cohort brand is recorded.

Email local parts are replaced with "redacted" (domains are kept because the free-email
heuristic depends on them). Large npm/PyPI documents are trimmed to the fields the
scanner reads, so a fixture stays small while keeping the upstream shape.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
USER_AGENT = "agentic-perimeter-fixture-recorder (+https://github.com/jonadas-tech/agentic-perimeter)"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

DOH = "https://dns.google/resolve?name={name}&type={rtype}{do}"
DNS_QUERIES = [
    ("example.com", "A", True),
    ("_agent-nx-9f8e7d.example.com", "TXT", False),
    ("_agent.example.com", "SVCB", True),
    ("_agent.example.com", "TXT", True),
    ("_agent.example.com", "SRV", True),
    ("_mcp.example.com", "SVCB", True),
    ("_mcp.example.com", "TXT", True),
    ("_mcp.example.com", "SRV", True),
    ("_mcp._tcp.example.com", "SRV", True),
    ("_mcp._tcp.example.com", "TXT", True),
]

SOURCES: Dict[str, List[str]] = {
    "mcp_registry": [
        "https://registry.modelcontextprotocol.io/v0.1/servers?search=agentic-perimeter&limit=100",
    ],
    "npm_search": [
        "https://registry.npmjs.org/-/v1/search?text=%40modelcontextprotocol%2Fsdk&size=1",
    ],
    "npm_package": [
        # Same encoding as vector1_supply_chain._fetch_npm_exact (quote(name, safe="@")).
        "https://registry.npmjs.org/@modelcontextprotocol%2Fsdk",
    ],
    "pypi": [
        "https://pypi.org/pypi/agentic-perimeter/json",
    ],
    "github": [
        "https://api.github.com/users/jonadas-tech",
    ],
    "doh": [
        DOH.format(name=urllib.parse.quote(n), rtype=t, do="&do=1" if d else "") for n, t, d in DNS_QUERIES
    ],
}


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return EMAIL_RE.sub(lambda m: f"redacted@{m.group(1)}", obj)
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    return obj


def _trim_npm_package(doc: Dict[str, Any]) -> Dict[str, Any]:
    latest = (doc.get("dist-tags") or {}).get("latest")
    time_map = doc.get("time") or {}
    return {
        "name": doc.get("name"),
        "description": doc.get("description"),
        "dist-tags": {"latest": latest},
        "time": {k: time_map[k] for k in ("created", "modified", latest) if k in time_map},
        "versions": {latest: {"name": doc.get("name"), "version": latest}} if latest else {},
        "maintainers": doc.get("maintainers"),
        "homepage": doc.get("homepage"),
        "repository": doc.get("repository"),
        "_trimmed": "versions/time reduced to the latest release by record_fixtures.py",
    }


def _trim_pypi(doc: Dict[str, Any]) -> Dict[str, Any]:
    info = doc.get("info") or {}
    keep = ("name", "version", "summary", "author", "author_email", "maintainer", "maintainer_email",
            "home_page", "project_urls", "package_url")
    return {
        "info": {k: info.get(k) for k in keep},
        "_trimmed": "releases/urls dropped by record_fixtures.py",
    }


TRIMMERS = {"npm_package": _trim_npm_package, "pypi": _trim_pypi}


def _fetch(url: str) -> Dict[str, Any]:
    accept = "application/dns-json" if "dns.google" in url else "application/json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=20) as resp:
        status = resp.status
        ctype = resp.headers.get("content-type", "")
        body = json.loads(resp.read().decode("utf-8"))
    return {"url": url, "status": status, "content_type": ctype, "body": body}


def main() -> int:
    recorded_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for source, urls in SOURCES.items():
        entries = []
        for url in urls:
            entry = _fetch(url)
            trim = TRIMMERS.get(source)
            if trim:
                entry["body"] = trim(entry["body"])
            entry["body"] = _scrub(entry["body"])
            entries.append(entry)
        out = {"source": source, "recorded_at": recorded_at, "responses": entries}
        (HERE / f"{source}.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
        print(f"recorded {source}: {len(entries)} response(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
