"""Contract tests against recorded upstream API responses (tests/fixtures/upstream/).

These catch upstream schema drift (npm, PyPI, Official MCP Registry, GitHub, DNS-over-HTTPS)
that unit tests with hand-written payloads cannot. Re-record with
`python tests/fixtures/upstream/record_fixtures.py` and review the diff: a changed field
here means the scanner's parsing assumptions need re-checking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from agentic_perimeter.dns_ct import doh_query, probe_dns_aid
from agentic_perimeter.http_client import HttpResponse, PoliteHttpClient
from agentic_perimeter.models import BrandTarget
from agentic_perimeter.vector1_supply_chain import (
    _check_github_owner_anchored,
    _extract_email_domain,
    _fetch_npm_exact,
    probe_vector1,
)

FIXTURES = Path(__file__).parent / "fixtures" / "upstream"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(source: str) -> List[Dict[str, Any]]:
    return json.loads((FIXTURES / f"{source}.json").read_text())["responses"]


def _body(source: str, index: int = 0) -> Any:
    return _load(source)[index]["body"]


class FixtureClient(PoliteHttpClient):
    """Real client behavior (locks, github_api_json) with recorded responses instead of network."""

    def __init__(self) -> None:
        super().__init__(github_token="unused", certspotter_token="unused", enable_github_search=False)
        self.responses: Dict[str, Dict[str, Any]] = {}
        for path in FIXTURES.glob("*.json"):
            for r in json.loads(path.read_text())["responses"]:
                self.responses[r["url"]] = r
        self.requested: List[str] = []

    def get(self, url: str, **kwargs: Any) -> HttpResponse:  # type: ignore[override]
        self.requested.append(url)
        r = self.responses.get(url)
        if r is None:
            return HttpResponse(url=url, final_url=url, status=404, headers={}, body_text="")
        return HttpResponse(
            url=url,
            final_url=url,
            status=int(r["status"]),
            headers={"content-type": r["content_type"]},
            body_text=json.dumps(r["body"]),
        )


def test_mcp_registry_v01_response_shape() -> None:
    body = _body("mcp_registry")
    assert isinstance(body["servers"], list) and body["servers"]
    assert isinstance(body.get("metadata"), dict)
    item = body["servers"][0]
    srv = item["server"]
    assert isinstance(srv["name"], str) and isinstance(srv["version"], str)
    assert isinstance(srv.get("packages", []), list)
    pkg = srv["packages"][0]
    assert {"registryType", "identifier"} <= set(pkg)
    official = item["_meta"]["io.modelcontextprotocol.registry/official"]
    assert isinstance(official["isLatest"], bool)
    assert official["status"] in ("active", "deprecated", "deleted")


def test_probe_vector1_requests_the_recorded_registry_url_and_parses_it() -> None:
    client = FixtureClient()
    v1, _findings = probe_vector1(client, BrandTarget(domain="jonadas.com", brand="agentic-perimeter"), ["jonadas.com"], {})
    registry_url = _load("mcp_registry")[0]["url"]
    assert registry_url in client.requested, "registry query URL format changed"
    assert not any("page_0" in e for e in v1["mcp_registry"].get("errors", [])), v1["mcp_registry"]["errors"]


def test_npm_search_response_still_exposes_fields_the_scanner_reads() -> None:
    obj = _body("npm_search")["objects"][0]
    pkg = obj["package"]
    for key in ("name", "version", "description", "links", "maintainers"):
        assert key in pkg, key
    assert "repository" in pkg["links"] and "homepage" in pkg["links"]
    assert all("email" in m for m in pkg["maintainers"])
    # Unscoped-package filtering depends on monthly downloads being present in search results.
    assert isinstance((obj.get("downloads") or {}).get("monthly"), int)
    assert _extract_email_domain(pkg["publisher"]["email"]) is not None


def test_npm_package_document_parses_into_an_anchored_official_package() -> None:
    client = FixtureClient()
    doc = _body("npm_package")
    pkg = _fetch_npm_exact(client, doc["name"], ["modelcontextprotocol.io"], {})
    assert pkg is not None
    assert pkg["version"] == doc["dist-tags"]["latest"]
    assert pkg["is_scoped"] is True
    assert pkg["anchoring_signals"]["maintainer_email"] is True
    assert pkg["official_anchored"] is True
    assert pkg["free_email_maintainer"] is False


def test_pypi_json_info_fields_the_scanner_reads() -> None:
    info = _body("pypi")["info"]
    for key in ("name", "version", "summary", "author_email", "maintainer_email", "home_page", "project_urls", "package_url"):
        assert key in info, key


def test_documentation_path_published_on_pypi_still_exists_in_repo() -> None:
    # PyPI metadata for released versions is immutable; renaming this file breaks the PyPI link.
    doc_url = _body("pypi")["info"]["project_urls"]["Documentation"]
    rel = doc_url.split("/blob/main/", 1)[1]
    assert (REPO_ROOT / rel).is_file(), f"{rel} is linked from PyPI metadata and must not be renamed"


def test_github_owner_lookup_falls_back_to_users_endpoint() -> None:
    client = FixtureClient()
    info = _check_github_owner_anchored(client, "jonadas-tech", ["example.org"], {})
    assert info["status"] == 200
    assert info["type"] == _body("github")["type"]
    assert {"blog", "email", "domain_anchored"} <= set(info)
    assert any(u.endswith("/orgs/jonadas-tech") for u in client.requested)
    assert any(u.endswith("/users/jonadas-tech") for u in client.requested)


def test_doh_json_answer_parsing_and_dnssec_flag() -> None:
    client = FixtureClient()
    res = doh_query(client, "example.com", "A", dnssec=True)
    assert res["ok"] is True
    assert res["status"] == 0
    assert res["ad"] is True
    assert res["answers"], "example.com A answers should parse"


def test_probe_dns_aid_end_to_end_against_recorded_doh() -> None:
    client = FixtureClient()
    res = probe_dns_aid(client, "example.com")
    assert res["apex_dnssec_ad"] is True
    assert res["dns_aid_present"] is False
    doh_urls = {r["url"] for r in _load("doh")}
    assert doh_urls <= set(client.requested), "DoH query URL format changed"
