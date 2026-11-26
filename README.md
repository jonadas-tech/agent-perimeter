# `agentic-perimeter`

<!-- mcp-name: io.github.jonadas-tech/agentic-perimeter -->

**See what AI agents and developers find when they look for your company's MCP servers on the public internet, and which of those things you don't control.**

[![CI](https://github.com/jonadas-tech/agentic-perimeter/actions/workflows/ci.yml/badge.svg)](https://github.com/jonadas-tech/agentic-perimeter/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agentic-perimeter.svg)](https://pypi.org/project/agentic-perimeter/)
[![DOI](https://zenodo.org/badge/1466570059.svg)](https://doi.org/10.5281/zenodo.24545374)
[![Glama MCP Server](https://glama.ai/mcp/servers/jonadas-tech/agentic-perimeter/badges/score.svg)](https://glama.ai/mcp/servers/jonadas-tech/agentic-perimeter)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/jonadas-tech/agentic-perimeter/blob/main/LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](https://github.com/jonadas-tech/agentic-perimeter/blob/main/pyproject.toml)

AI coding assistants increasingly connect to services through the [Model Context Protocol](https://modelcontextprotocol.io) (MCP). To do that, they look a company up in public places: the Official MCP Registry, npm, PyPI, and DNS. Anyone can publish there under your company's name. `agentic-perimeter` checks those places for one domain and reports:

- **Which MCP entries and packages carrying your name are verifiably yours**, and which are published by third parties (including hosted relays that would handle your users' API tokens).
- **Whether your own public MCP endpoints** (for example `mcp.yourdomain.com`) tell connecting clients which login server to trust.
- **Whether your DNS is signed**, and whether agent-themed lookalike domains are live or already flagged for phishing.

It only reads public data: no logins, no port scanning, no calls to anyone's MCP tools, and no execution of downloaded code. It has no runtime dependencies beyond the Python 3.11+ standard library.

## Example output

![Top of the HTML brief for the fictional domain acme-payments.example: first-party grade B (88/100) next to critical third-party pressure (85/100), with counts of official vs. third-party registry entries, unverified packages, live MCP endpoints, and lookalike domains](https://raw.githubusercontent.com/jonadas-tech/agentic-perimeter/main/docs/assets/sample-report-fictional-domain.jpg)

*Top of the offline HTML brief for a fictional domain. The two scores are separate on purpose: a company can have good controls of its own and still face heavy third-party activity around its name. The same results are available as JSON and SARIF.*

## Quickstart

Run directly from PyPI with [`uvx`](https://docs.astral.sh/uv/) (no install required):

```bash
uvx agentic-perimeter audit yourdomain.com --html report.html
```

Open `report.html` in a browser. Every finding links to the public evidence it was based on (registry entry, package page, DNS answer, or certificate).

More options:

```bash
# JSON + HTML brief + SARIF (for GitHub Code Scanning) + Protective DNS policy files
uvx agentic-perimeter audit example.com \
  --json report.json \
  --html report.html \
  --sarif report.sarif \
  --rpz policy.rpz \
  --domain-feed feed.json \
  --rpz-mode block

# Include passive in-memory static inspection of up to 10 unverified npm/PyPI tarballs
uvx agentic-perimeter audit example.com \
  --inspect-packages \
  --json report.json

# Continuous monitoring: diff against a saved baseline and exit 2 on new exposures
uvx agentic-perimeter audit example.com \
  --baseline baseline.json \
  --fail-on-new \
  --sarif report.sarif

# Longitudinal cohort trend analysis (supports raw batch JSON or anonymized study JSON)
uvx agentic-perimeter trend \
  cohort_2026_q4.json cohort_2027_q1.json \
  --label-prev 2026-Q4 --label-curr 2027-Q1 \
  --json trend.json --md trend.md
```

Batch-audit a list of domains and emit an anonymized dataset + Markdown summary:

```bash
uvx agentic-perimeter batch datasets/top100_brands.json \
  --output raw_batch.json \
  --anonymized-out study_anonymized.json \
  --study-md study_summary.md \
  --workers 8
```

Optional environment variables:
- `GITHUB_TOKEN` (or authenticated `gh` CLI) for GitHub org domain anchoring (`blog`/`email`) and higher rate limits.
- `CERTSPOTTER_API_KEY` for higher CertSpotter Certificate Transparency throughput (falls back automatically to bounded `crt.sh` + live TLS SAN extraction).

---

## Run as an MCP Server (Claude Code, Cursor, VS Code, Windsurf)

`agentic-perimeter` includes a built-in, zero-dependency, strictly read-only MCP `stdio` server (`readOnlyHint: true`, `destructiveHint: false`) exposing `audit_domain` and `lint_dns_aid`:

```json
{
  "mcpServers": {
    "agentic-perimeter": {
      "command": "uvx",
      "args": ["agentic-perimeter", "mcp"]
    }
  }
}
```

---

## Continuous Monitoring in GitHub Actions (SARIF + Baseline Diff)

Drop a weekly passive check into `.github/workflows/agentic-perimeter.yml` to surface new external MCP exposures directly in GitHub Code Scanning:

```yaml
name: External Agentic Perimeter Monitor

on:
  schedule:
    - cron: "0 12 * * 1" # Every Monday at 12:00 UTC
  workflow_dispatch:

permissions:
  security-events: write
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Run passive external MCP audit
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          uvx --python 3.12 agentic-perimeter audit example.com \
            --json latest.json \
            --html latest.html \
            --sarif agentic-perimeter.sarif
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentic-perimeter.sarif
```

---

## How it works

The terms used in reports, in one line each:

- **MCP (Model Context Protocol):** the open protocol AI assistants use to call external tools and services.
- **Official MCP Registry:** the public directory at `registry.modelcontextprotocol.io`; entries named in your reverse-DNS namespace (for example `com.yourcompany/...`) can be verified as yours.
- **Hosted proxy:** a third-party MCP endpoint that relays requests to your API on the user's behalf, usually holding the user's token.
- **Free-email maintainer:** a package published from a consumer email address (Gmail, Outlook, etc.). A weak signal on its own; see [Limitations](docs/LIMITATIONS.md).
- **RFC 9728 (OAuth Protected Resource Metadata):** a small file at `/.well-known/oauth-protected-resource` that tells clients which authorization server may issue tokens for an endpoint.
- **DNSSEC:** cryptographic signing of DNS answers, so clients can tell a forged answer from a real one.
- **DNS-AID:** an early IETF Internet-Draft for publishing agent endpoints in DNS; reported for readiness only.
- **RPZ (Response Policy Zone):** a standard format for DNS blocklists; `--rpz` exports confirmed lookalikes for protective DNS resolvers.
- **SARIF:** the standard format GitHub Code Scanning reads.
- **Two-axis score:** *First-Party Control Posture* (grade A to F, what your own teams control; N/A when you have no MCP footprint) and *External Threat Pressure* (None to Critical, what third parties have done around your name). They are kept separate so popular platforms are not penalized for attracting community wrappers, and companies with no footprint do not receive an unearned A.

### What it audits

| Vector | Focus | Passive Signals Verified | OWASP Mapping |
|---|---|---|---|
| **V1 (Primary)** | **MCP Supply-Chain & Brand Provenance** | Correlates Official MCP Registry (`/v0.1/servers` via broad + targeted reverse-DNS queries), npm, PyPI, and GitHub. Anchors official assets via reverse-DNS, verified sibling domains, GitHub org `blog`/`email`, and cross-registry maintainer emails; strips hosting prefixes (`io.github.*`, `app.vercel.*`, `dev.workers.*`), skips unpublished tombstones, separates `0.0.1-security` holding packages, and filters homonyms. Flags **URL-Path Token Exposure**, **Unverified 3rd-Party Hosted Proxy**, **Unverified Package / Free-Email Maintainer**, and **Official Registry Vacuum**, with passive RFC 9083 RDAP domain-age/registrar profiling (`NOD <30d` / `<90d`; disable via `--no-rdap`). Optional `--inspect-packages` statically inspects public tarballs/wheels in memory (`<=5 MB`, zero execution). | `ASI03`, `ASI04`, `ASI05`, `ASI07`, `ASI09` / `MCP01:2025`, `MCP04:2025`, `MCP05:2025`, `MCP09:2025` |
| **V2 (Secondary)** | **External Perimeter, Wire-Level DNS-AID / ANS v2 & OAuth Hygiene** | Queries DoH (`do=1`) for wire-level IETF DNS-AID (`draft-02`: `_index._agents`, `catalog.<domain>` separation, RFC 9460 `SVCB` private keys `key65400`/`key65401`/`key65402`/`key65405`, passive `cap-sha256` card integrity verification), apex DNSSEC (`AD=true`), DANE `_443._tcp` `TLSA`, ANS v2 `_ans-badge` host-binding verification, and complementary Chain-of-Trust surfaces (`/.well-known/ard.json`, `/.well-known/ucp`, SPIFFE bundles/SVIDs, `_agent-keys` TXT). Discovers active `mcp.*`/`agents.*` endpoints via CertSpotter CT (`crt.sh` fallback) and live TLS SANs; checks RFC 9728 (`/.well-known/oauth-protected-resource` and `WWW-Authenticate` `resource_metadata`), **Broad OAuth Scope Declaration**, and **Cross-Domain Perimeter Drift**. | `ASI03`, `ASI04`, `ASI07` / `MCP02:2025`, `MCP07:2025`, `MCP09:2025` |
| **V3 (Silent Sub-Check)** | **Active Lookalike Infrastructure** | Suppresses domain parking, HTTP 523 squatters, defensive brand registrations, and HTML catch-alls. Emits findings only for **Active Lookalike Agent Endpoint** (`/.well-known/mcp.json` or live JSON-RPC/SSE `/mcp`), **Spoofed `_ans-badge` Host-Binding Mismatch** on lookalike agent hosts, or **Phishing-Warning Lookalike Domain** (HTTP 403/451 third-party warning interstitials), enriched with passive RDAP registration age. | `ASI04`, `ASI07`, `ASI09` / `MCP04:2025`, `MCP09:2025` |

---

### Outputs & risk model

`agentic-perimeter` produces six artifacts: **structured JSON** (schema `2.0`), **SARIF 2.1.0**, **baseline diff output**, a **self-contained single-file HTML executive brief** (zero external CDN dependencies, print-to-PDF ready), **open-standard Protective DNS RPZ & JSON domain feeds** (`--rpz`, `--domain-feed`, `--rpz-mode {block,audit}`, with `rpz-passthru.` allowlists for verified first-party endpoints and self-DoS protection keeping shared multi-tenant cloud platforms audit-only), and **longitudinal cohort trend reports** (`agentic-perimeter trend`).

Every audit reports two independent operational dimensions mapped to an **Action Posture** and split by remediation owner (**Platform / API Engineering** vs. **SecOps / Brand Protection**):

- **First-Party Control Posture (`0–100`, Grade `A–F` or `N/A Baseline`):** Measures controllable first-party hygiene across six checks (`C1` Official MCP Registry, `C2` Official Scoped Packages, `C3` RFC 9728 Coverage, `C4` Least-Privilege OAuth Scopes, `C5` Domain Boundary Consistency, `C6` DNSSEC & IETF DNS-AID). Organizations with zero external agentic footprint receive `N/A Baseline`.
- **External Ecosystem Threat Pressure (`0–100`, `None`–`Critical`):** Measures third-party exposure signals targeting the brand (`T1` URL-Path Token Exposure, `T2` Unverified 3P Proxies, `T3` Free-Email Maintainer Collisions, `T4` Unverified Packages, `T5` Active Lookalike Agent Endpoints, `T6` Phishing-Warning Lookalikes).

---

## Limitations & false positives

The classifications are heuristics over public metadata, and a "third-party" or "unverified" label can be wrong. Known limits (no hand-labelled precision estimate yet, free-email is a weak signal, calibration brands inside the study sample, bounded registry search, signature-only package checks) are documented in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

If the tool mislabels something you own or maintain, please [report a false positive](https://github.com/jonadas-tech/agentic-perimeter/issues/new?template=false_positive.yml). Do not post live security misconfigurations in public issues; use a [private security advisory](https://github.com/jonadas-tech/agentic-perimeter/security/advisories/new) instead.

---

## Empirical Study: *State of External Agentic Exposure*, November 2026 baseline

![State of External Agentic Exposure, November 2026 baseline: Top 100 Brands Overview](https://raw.githubusercontent.com/jonadas-tech/agentic-perimeter/main/docs/assets/top100_exposure_chart.svg)

*Naming note:* the scan ran on 21 November 2026 (census on 23 November). File names, the dataset `study_title`, and the Zenodo record keep the original "2027" identifier because they are already referenced from PyPI metadata, the archived DOI, and external links; the study itself is the **November 2026 baseline**.

I ran a 100% passive baseline across **100 major public brands** (`50` traditional Fortune Global 500 / S&P 500 enterprises + `50` SaaS, Fintech, Cloud, Cybersecurity, and AI brands; curated sample, [list](https://github.com/jonadas-tech/agentic-perimeter/blob/main/datasets/top100_brands.json)), followed by a read-only in-memory static census of **632 of 642 unique unverified brand-named npm/PyPI MCP packages** discovered in the cohort:

- **Narrative study (canonical):** [The MCP Servers You Didn't Ship](https://www.jonadas.com/writing/research/state-of-external-agentic-exposure-2026-baseline), with method and limits
- **Full anonymized report:** [`docs/state_of_external_agentic_exposure_2027.md`](https://github.com/jonadas-tech/agentic-perimeter/blob/main/docs/state_of_external_agentic_exposure_2027.md)
- **Anonymized brand dataset (`N=100`):** [`datasets/study_2027_anonymized.json`](https://github.com/jonadas-tech/agentic-perimeter/blob/main/datasets/study_2027_anonymized.json)
- **Anonymized package static census (`N=632`):** [`datasets/static_census_2027_anonymized.json`](https://github.com/jonadas-tech/agentic-perimeter/blob/main/datasets/static_census_2027_anonymized.json)

### Key Verified Findings

| Metric | All Brands (N=100) | Traditional Fortune/S&P 500 (N=50) | SaaS / Fintech / Cloud / AI (N=50) |
|---|---:|---:|---:|
| External MCP ecosystem footprint | **58.0%** | 20.0% | 96.0% |
| Official domain-anchored MCP Registry entry | **25.0%** | 6.0% | 44.0% |
| **Official Registry Vacuum** (0 official + >=1 unverified 3P) | **33.0%** *(56.9% of MCP-active)* | 14.0% *(70.0% of MCP-active)* | 52.0% |
| **Unverified 3rd-Party Hosted MCP Proxy** claiming brand | **39.0%** | 14.0% | 64.0% |
| **Free-Email Maintainer** on unverified MCP package | **50.0%** | 10.0% | 90.0% |
| Live first-party `mcp.*` / `agents.*` endpoint | **29.0%** | 4.0% *(2 of 50)* | 54.0% |
| **Missing RFC 9728** among live MCP endpoints | **13.8%** *(4 of 29)* | 2 of 2 *(too few endpoints to compare)* | 7.4% *(2 of 27)* |
| Apex DNSSEC validated (`AD=true`) | **18.0%** | 12.0% | 24.0% |

Percentages for the 50-brand cohorts move by 2 points per brand; treat cohort differences smaller than about 10 points as noise.

**Highlights from the 632-Package In-Memory Static Census (`98.4%` of all `642` unverified packages):**
- **`0.0%` (`0/632`)** contained hidden prompt-injection or Unicode Tag payloads. This is a signature check on package files, so it cannot see novel phrasings or tool descriptions served at runtime; within what is statically inspectable, the measurable exposure is classical provenance and governance failure.
- **`23.7%` (`150/632`)** ship **no source repository URL** in package metadata.
- **`29` individual maintainer accounts** each publish unverified MCP packages targeting **3 to 23 distinct Top-100 brands** (top two accounts control `24` packages across `23` brands and `18` packages across `18` brands), alongside a **`22`-package dormant `coming-soon` placeholder cluster** (`3.5%`) spanning `13` Top-100 brands and **`5` prior npm Security `0.0.1-security` holding packages** (`10.0%` of the Tech/SaaS cohort).
- **`18.5%` (`117/632`)** declare lifecycle hooks (`3` `postinstall` remote binary downloaders, `1` without SHA-256 verification), **`17.2%` (`109/632`)** invoke shell/subprocess execution, **`4.1%` (`26/632`)** reference local AI agent config files (`.cursor/mcp.json`, `claude_desktop_config.json`, `.codex/config.toml`), and **`1.7%` (`11/632`)** register unrelated CLI `bin` commands.

---

## Development & Testing

```bash
uv run --python 3.12 pytest -v
```

`tests/test_upstream_contracts.py` runs the real parsers against recorded responses from the Official MCP Registry, npm, PyPI, GitHub, and DNS-over-HTTPS (`tests/fixtures/upstream/`). To check for upstream schema changes, re-record and review the diff:

```bash
python tests/fixtures/upstream/record_fixtures.py
uv run --python 3.12 pytest tests/test_upstream_contracts.py -v
```

The recorder only targets neutral sources (this tool's own PyPI and registry entries, the official MCP SDK on npm, and `example.com` for DNS) and redacts email local parts.

## Responsible Disclosure & Neutrality

All published study datasets strip target domain/brand identifiers and sensitive live misconfiguration URLs, assign record IDs in random order, and merge sectors with fewer than 5 brands. Versions of `study_2027_anonymized.json` before 2026-11-25 (in git history and the Zenodo v0.3.1 archive) assigned IDs in input-list order and can be re-identified against the public brand list; see [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Classifications describe verifiable provenance properties and never assert malicious intent by commercial aggregators or community maintainers. See [SECURITY.md](https://github.com/jonadas-tech/agentic-perimeter/blob/main/SECURITY.md) for full passive-only guarantees and disclosure policy.

## License

Apache-2.0 — see [LICENSE](https://github.com/jonadas-tech/agentic-perimeter/blob/main/LICENSE).
