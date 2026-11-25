"""Tests for Vector 1 official anchoring, noise/homonym filtering, and finding classes."""

from __future__ import annotations

import json
import threading
from typing import Any, Dict, Optional, Tuple

from agentic_perimeter.http_client import HttpResponse
from agentic_perimeter.models import BrandTarget
from agentic_perimeter.vector1_supply_chain import probe_vector1


class FakeHttpClient:
    """Deterministic passive HTTP mock for unit testing."""

    def __init__(self, responses: Dict[str, HttpResponse], gh_responses: Dict[str, Tuple[int, Any, Optional[str]]]) -> None:
        self._responses = responses
        self._gh = gh_responses
        self._meta_lock = threading.Lock()
        self.github_token = "test-token"
        self.certspotter_token = None
        self.stats: Dict[str, Dict[str, int]] = {}

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        if url in self._responses:
            return self._responses[url]
        return HttpResponse(url=url, final_url=url, status=404, headers={}, body_text="")

    def github_api_json(self, endpoint: str, is_search: bool = False) -> Tuple[int, Any, Optional[str]]:
        key = endpoint.lstrip("/")
        if key in self._gh:
            return self._gh[key]
        return 404, None, "http_404"


def _json_resp(url: str, payload: Any, status: int = 200) -> HttpResponse:
    return HttpResponse(
        url=url,
        final_url=url,
        status=status,
        headers={"content-type": "application/json"},
        body_text=json.dumps(payload),
    )


def test_official_anchoring_notion_snowflake_mongodb_and_noise_filtering() -> None:
    # 1. Notion: com.notion/mcp anchored via verified sibling notion.com + @notionhq anchored via makenotion GitHub org
    notion_reg = {
        "servers": [
            {
                "server": {
                    "name": "com.notion/mcp",
                    "version": "1.0.0",
                    "title": "Notion MCP",
                    "remotes": [{"type": "streamable-http", "url": "https://mcp.notion.com/mcp"}],
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True, "status": "active"}},
            },
            {
                "server": {
                    "name": "com.insightfulpipe/notion",
                    "version": "1.0.0",
                    "title": "Notion",
                    "remotes": [{"type": "streamable-http", "url": "https://notion.insightfulmcp.com/"}],
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True, "status": "active"}},
            },
        ]
    }
    notion_npm = {
        "objects": [
            {
                "package": {
                    "name": "@notionhq/notion-mcp-server",
                    "version": "2.0.0",
                    "description": "Official Notion MCP server",
                    "publisher": {"username": "github-actions", "email": "noreply@github.com"},
                    "maintainers": [{"name": "notion", "email": "noreply@github.com"}],
                    "links": {"repository": "https://github.com/makenotion/notion-mcp-server"},
                },
                "downloads": {"monthly": 1300000},
            },
            {
                "package": {
                    "name": "notion-mcp-server",
                    "version": "1.0.0",
                    "description": "Community Notion MCP server",
                    "publisher": {"username": "dev1", "email": "dev1@gmail.com"},
                    "maintainers": [{"name": "dev1", "email": "dev1@gmail.com"}],
                    "links": {"repository": "https://github.com/awkoy/notion-mcp-server"},
                },
                "downloads": {"monthly": 22000},
            },
        ]
    }
    client = FakeHttpClient(
        responses={
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=notion&limit=100": _json_resp(
                "https://registry.modelcontextprotocol.io/v0.1/servers?search=notion&limit=100", notion_reg
            ),
            "https://registry.npmjs.org/-/v1/search?text=notion%20mcp&size=25": _json_resp(
                "https://registry.npmjs.org/-/v1/search?text=notion%20mcp&size=25", notion_npm
            ),
        },
        gh_responses={
            "orgs/makenotion": (200, {"type": "Organization", "blog": "https://www.notion.so", "email": ""}, None),
            "orgs/awkoy": (404, None, "http_404"),
            "users/awkoy": (200, {"type": "User", "blog": ""}, None),
        },
    )
    target = BrandTarget(domain="notion.so", brand="notion", aliases=["notion"])
    v1, findings = probe_vector1(client, target, ["notion.com", "notion.so"], {})

    assert v1["mcp_registry"]["official_count"] == 1
    assert v1["mcp_registry"]["unverified_3p_hosted_proxy_count"] == 1
    assert v1["flags"]["official_registry_vacuum"] is False
    assert v1["npm"]["official_count"] == 1
    assert v1["npm"]["unverified_count"] == 1
    assert v1["npm"]["free_email_unverified_count"] == 1
    rule_ids = {f.rule_id for f in findings}
    assert "v1_unverified_3p_hosted_proxy" in rule_ids
    assert "v1_unscoped_free_email_collision" in rule_ids
    assert "v1_official_registry_vacuum" not in rule_ids


def test_snowflake_labs_mongodb_js_and_noise_filters() -> None:
    # Snowflake: Snowflake-Labs anchored via GitHub org; sadri-dridi sensor & distributed-id homonym filtered
    sf_reg = {
        "servers": [
            {
                "server": {
                    "name": "io.github.Snowflake-Labs/mcp",
                    "version": "1.0.0",
                    "repository": {"url": "https://github.com/Snowflake-Labs/mcp"},
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True}},
            },
            {
                "server": {
                    "name": "io.github.sadri-dridi/snowflake-ok",
                    "version": "1.0.0",
                    "remotes": [
                        {"type": "streamable-http", "url": "https://agent-observatory-sensor.nolimit-observatory.workers.dev/s/snowflake-ok/mcp"}
                    ],
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True}},
            },
            {
                "server": {
                    "name": "io.github.alphaparkinc/genpark-distributed-id-snowflake-generator-skill",
                    "version": "1.0.0",
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True}},
            },
        ]
    }
    client = FakeHttpClient(
        responses={
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=snowflake&limit=100": _json_resp(
                "https://registry.modelcontextprotocol.io/v0.1/servers?search=snowflake&limit=100", sf_reg
            ),
            "https://registry.npmjs.org/-/v1/search?text=snowflake%20mcp&size=25": _json_resp(
                "https://registry.npmjs.org/-/v1/search?text=snowflake%20mcp&size=25", {"objects": []}
            ),
        },
        gh_responses={
            "orgs/Snowflake-Labs": (
                200,
                {"type": "Organization", "blog": "https://developers.snowflake.com/", "email": "opensource@snowflake.com", "is_verified": True},
                None,
            )
        },
    )
    v1, findings = probe_vector1(client, BrandTarget(domain="snowflake.com", brand="snowflake"), ["snowflake.com"], {})
    assert v1["mcp_registry"]["official_count"] == 1
    assert v1["mcp_registry"]["unverified_3p_hosted_proxy_count"] == 0
    assert v1["mcp_registry"]["noise_filtered_count"] == 2
    assert findings == []


def test_mongodb_cross_registry_npm_maintainer_anchoring_and_no_free_email_fp() -> None:
    mg_reg = {
        "servers": [
            {
                "server": {
                    "name": "io.github.mongodb-js/mongodb-mcp-server",
                    "version": "1.0.0",
                    "repository": {"url": "https://github.com/mongodb-js/mongodb-mcp-server"},
                    "packages": [{"registryType": "npm", "identifier": "mongodb-mcp-server", "version": "1.0.0"}],
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True}},
            }
        ]
    }
    mg_npm_exact = {
        "name": "mongodb-mcp-server",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {}},
        "description": "MongoDB MCP Server",
        "maintainers": [
            {"name": "devtools", "email": "devtools@mongodb.com"},
            {"name": "eng", "email": "personal@gmail.com"},
        ],
        "repository": {"url": "https://github.com/mongodb-js/mongodb-mcp-server"},
    }
    client = FakeHttpClient(
        responses={
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=mongodb&limit=100": _json_resp(
                "https://registry.modelcontextprotocol.io/v0.1/servers?search=mongodb&limit=100", mg_reg
            ),
            "https://registry.npmjs.org/-/v1/search?text=mongodb%20mcp&size=25": _json_resp(
                "https://registry.npmjs.org/-/v1/search?text=mongodb%20mcp&size=25", {"objects": []}
            ),
            "https://registry.npmjs.org/mongodb-mcp-server": _json_resp(
                "https://registry.npmjs.org/mongodb-mcp-server", mg_npm_exact
            ),
        },
        gh_responses={
            "orgs/mongodb-js": (200, {"type": "Organization", "blog": "https://github.com/mongodb-js/mongodb-js"}, None)
        },
    )
    v1, findings = probe_vector1(client, BrandTarget(domain="mongodb.com", brand="mongodb"), ["mongodb.com"], {})
    assert v1["mcp_registry"]["official_count"] == 1
    assert v1["npm"]["official_count"] == 1
    # Official package with 1 gmail maintainer alongside @mongodb.com must NOT trigger free_email FP
    assert v1["npm"]["free_email_unverified_count"] == 0
    assert findings == []


def test_url_path_token_exposure_and_ai_sdk_noise_filter() -> None:
    stripe_reg = {
        "servers": [
            {
                "server": {
                    "name": "eu.nordicmcp/stripe",
                    "version": "1.0.0",
                    "title": "Stripe Proxy",
                    "remotes": [{"type": "streamable-http", "url": "https://nordicmcp.eu/mcp/stripe/{token}"}],
                },
                "_meta": {"io.modelcontextprotocol.registry/official": {"isLatest": True}},
            }
        ]
    }
    # Verify generic `ai` package is NEVER matched for stripe/anthropic
    npm_noise = {
        "objects": [
            {
                "package": {
                    "name": "ai",
                    "version": "5.0.0",
                    "description": "AI SDK supporting stripe and anthropic mcp tools",
                    "publisher": {"username": "vercel", "email": "dev@vercel.com"},
                    "maintainers": [],
                    "links": {},
                },
                "downloads": {"monthly": 194000000},
            }
        ]
    }
    client = FakeHttpClient(
        responses={
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=stripe&limit=100": _json_resp(
                "https://registry.modelcontextprotocol.io/v0.1/servers?search=stripe&limit=100", stripe_reg
            ),
            "https://registry.npmjs.org/-/v1/search?text=stripe%20mcp&size=25": _json_resp(
                "https://registry.npmjs.org/-/v1/search?text=stripe%20mcp&size=25", npm_noise
            ),
        },
        gh_responses={},
    )
    v1, findings = probe_vector1(client, BrandTarget(domain="stripe.com", brand="stripe"), ["stripe.com"], {})
    assert v1["npm"]["total_relevant"] == 0  # `ai` SDK excluded!
    assert v1["flags"]["has_url_path_token_exposure"] is True
    assert v1["flags"]["official_registry_vacuum"] is True

    by_rule = {f.rule_id: f for f in findings}
    assert "v1_url_path_token_exposure" in by_rule
    assert by_rule["v1_url_path_token_exposure"].severity == "critical"
    assert by_rule["v1_url_path_token_exposure"].label == "URL-Path Token Exposure"
    owasp_codes = {o.code for o in by_rule["v1_url_path_token_exposure"].owasp}
    assert {"ASI03", "ASI04", "MCP01:2025", "MCP04:2025"} <= owasp_codes


def test_f1_to_f10_platform_prefix_spoof_tombstones_security_holding_and_homonyms() -> None:
    from agentic_perimeter.vector1_supply_chain import (
        _email_matches_domains,
        _is_homonym_noise,
        _is_security_holding_pkg,
        _matchable_registry_name,
    )

    # F1: Hosting-platform reverse-DNS prefixes stripped while preserving brand org names
    assert _matchable_registry_name("io.github.randomuser/cool-tool") == "randomuser/cool-tool"
    assert _matchable_registry_name("io.github.Snowflake-Labs/mcp") == "Snowflake-Labs/mcp"
    assert _matchable_registry_name("app.vercel.aididwhat/aididwhat") == "aididwhat/aididwhat"
    assert _matchable_registry_name("dev.workers.apexlabs-cloudflare.pagetext/pagetext") == "pagetext"
    assert _matchable_registry_name("io.github.github/github-mcp-server") == "github/github-mcp-server"
    assert _matchable_registry_name("com.vercel/mcp") == "com.vercel/mcp"

    # F3: GitHub noreply / GitHub Actions OIDC emails must never anchor github.com
    assert _email_matches_domains("12345+dev@users.noreply.github.com", ["github.com"]) is False
    assert _email_matches_domains("noreply@github.com", ["github.com"]) is False
    assert _email_matches_domains("security@github.com", ["github.com"]) is True

    # F5: Security holding package detection
    assert _is_security_holding_pkg("0.0.1-security", "security holding package") is True
    assert _is_security_holding_pkg("1.2.3", "Active MCP server") is False

    # F6-F10: Homonym filters
    assert _is_homonym_noise("com.ternvisa/australian-visas Visa processing", BrandTarget(domain="visa.com", brand="visa")) is True
    assert _is_homonym_noise("dev.moneytools/fidelity Inference Fidelity Audit", BrandTarget(domain="fidelity.com", brand="fidelity")) is True
    assert _is_homonym_noise("com.tidybutton/workday-calc Business Day Calculator", BrandTarget(domain="workday.com", brand="workday")) is True
    assert _is_homonym_noise("agent-intercom Let Claude Code message each other", BrandTarget(domain="intercom.com", brand="intercom")) is True
    assert _is_homonym_noise("mcp-sentry Static-analysis security linter", BrandTarget(domain="sentry.io", brand="sentry")) is True

    # F3 + F4 + F5 end-to-end: self-asserted homepage cannot anchor gmail pkg; unpublished tombstone skipped;
    # 0.0.1-security separated into security_holding_packages
    client = FakeHttpClient(
        responses={
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=acme&limit=100": _json_resp(
                "x", {"servers": []}
            ),
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=com.acme&limit=25": _json_resp(
                "x", {"servers": []}
            ),
            "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.acme&limit=25": _json_resp(
                "x", {"servers": []}
            ),
            "https://registry.npmjs.org/-/v1/search?text=acme%20mcp&size=25": _json_resp(
                "x",
                {
                    "objects": [
                        {
                            "package": {
                                "name": "acme-mcp-spoof",
                                "version": "1.0.0",
                                "description": "Unofficial Acme MCP server",
                                "publisher": {"username": "spoof", "email": "spoof@gmail.com"},
                                "maintainers": [{"name": "spoof", "email": "spoof@gmail.com"}],
                                "links": {"homepage": "https://www.acme.com/docs", "repository": "https://github.com/randomdev/acme-mcp"},
                            },
                            "downloads": {"monthly": 500},
                        }
                    ]
                },
            ),
            # F4: Unpublished tombstone
            "https://registry.npmjs.org/acme-mcp": _json_resp(
                "x", {"name": "acme-mcp", "time": {"unpublished": {"versions": ["0.0.1"]}}}
            ),
            # F5: npm Security holding package
            "https://registry.npmjs.org/mcp-server-acme": _json_resp(
                "x",
                {
                    "name": "mcp-server-acme",
                    "dist-tags": {"latest": "0.0.1-security"},
                    "versions": {"0.0.1-security": {}},
                    "description": "security holding package",
                    "maintainers": [{"name": "npm", "email": "npm@npmjs.com"}],
                },
            ),
        },
        gh_responses={"orgs/randomdev": (404, None, "http_404"), "users/randomdev": (200, {"type": "User", "blog": ""}, None)},
    )
    v1, _ = probe_vector1(client, BrandTarget(domain="acme.com", brand="acme"), ["acme.com"], {})
    assert v1["npm"]["official_count"] == 0  # homepage spoof rejected!
    assert v1["npm"]["unverified_count"] == 1  # only acme-mcp-spoof (tombstone skipped, holding separated!)
    assert v1["npm"]["free_email_unverified_count"] == 1
    assert v1["npm"]["security_holding_count"] == 1
    assert v1["npm"]["security_holding_packages"][0]["name"] == "mcp-server-acme"
