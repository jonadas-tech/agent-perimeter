# `agent-perimeter`

**100% passive External Attack Surface Management (EASM) CLI for agentic brand impersonation, MCP supply-chain provenance, and DNS-AID / OAuth perimeter hygiene.**

Existing open-source MCP security tools audit *local developer configurations* or *individual packages*. `agent-perimeter` takes the external CISO perspective: starting from a company's public domain, it audits what autonomous AI agents and developers encounter *outside* the corporate perimeter across public MCP registries, package ecosystems, DNS-AID/DNSSEC, Certificate Transparency, and OAuth metadata.

Mapped verbatim to **OWASP Top 10 for Agentic Applications (2026 v1.0)** and **OWASP MCP Top 10 (2025 v0.1 Beta)**.

---

## Quickstart (`uvx`)

Zero third-party runtime dependencies (Python 3.11+ standard library only):

```bash
# Audit a single domain and generate JSON + CISO-ready single-file HTML report
uvx --from . agent-perimeter audit example.com \
  --json example_report.json \
  --html example_report.html

# Batch-audit a cohort and emit an anonymized study dataset + Markdown summary
uvx --from . agent-perimeter batch datasets/top100_brands.json \
  --output raw_batch.json \
  --anonymized-out study_anonymized.json \
  --study-md study_summary.md \
  --workers 8
```

Optional environment variables for higher passive API throughput:
- `GITHUB_TOKEN` (or authenticated `gh` CLI) for GitHub org provenance verification (`blog`/`email` anchoring) and repo search.
- `CERTSPOTTER_API_KEY` for higher CertSpotter Certificate Transparency quota (gracefully falls back to bounded `crt.sh` and live TLS SAN extraction when unset).

---

## 2-Axis Scoring Model (`2-axis-v1`)

A single combined risk score penalizes popular brands for third-party ecosystem gravity while inflating zero-footprint enterprises to an unearned Grade `A`. `agent-perimeter` separates accountability across two orthogonal axes:

1. **Axis 1 — First-Party Control Posture (`0–100`, higher = better, Grade `A–F` or `N/A Baseline`):**
   - Evaluates 6 controllable first-party domains (`C1` Official MCP Registry Presence [35], `C2` Official Scoped/Anchored Packages [15], `C3` RFC 9728 OAuth Metadata Coverage [20], `C4` Least-Privilege OAuth Scope Hygiene [10], `C5` First-Party Domain Boundary Consistency [8], `C6` Cryptographic DNS Trust: DNSSEC +8 / DNS-AID +4 [12]), normalized strictly across applicable controls.
   - Organizations with zero external MCP footprint, no brand-named packages, and no live first-party MCP endpoints receive **`N/A (Baseline)`** instead of an inflated Grade `A`.
2. **Axis 2 — External Ecosystem Threat Pressure (`0–100`, higher = heavier pressure, `None / Low / Moderate / High / Critical` — strictly NO `A–F` grade):**
   - Measures purely external third-party pressure across `T1` URL-Path Token Exposure (35), `T2` Unverified 3P Hosted MCP Proxies (tiered 20/26/32, or 6 for package-only 3P registry entries), `T3` Free-Email Maintainer Collisions (tiered 14/18/22), `T4` Unverified Brand-Named Packages (tiered 6/9/12), `T5` Active Lookalike Agent Endpoint (50), and `T6` Phishing-Warning Lookalike Domain (25), capped at 100.
3. **2D Executive Action Posture & Owner-Split Priorities:**
   - Synthesizes both axes into an executive action state (`Well-Positioned`, `Active Monitoring`, `Active Defense`, `Targeted Hardening`, `Hardening & Monitoring`, `Priority Hardening`, `Proactive Hardening`, `Action Required`, `Urgent Remediation`, `Brand Protection Alert`, or `Baseline — Monitor`) with context-aware remediation split between **First-Party Controls (AppSec / IAM / DNS)** and **External Ecosystem Defense (Brand Protection / Governance)**.

---

## Passive Audit Vectors (v1 Scope)

| Vector | Focus | Concrete Signals Audited | OWASP Mapping |
|---|---|---|---|
| **V1 (Primary)** | **MCP Supply-Chain & Brand Provenance** | Correlates Official MCP Registry (`registry.modelcontextprotocol.io/v0.1/servers` with broad + targeted reverse-DNS anchor queries), npm, PyPI, and GitHub. Verifies first-party anchoring (reverse-DNS, verified sibling domains, GitHub org `blog`/`email`, cross-registry maintainer email), excludes unpublished tombstones and npm Security holding packages (`0.0.1-security`), and filters hosting prefixes & homonyms. Flags: **URL-Path Token Exposure**, **Unverified 3rd-Party Hosted Proxy**, **Unverified Package / Free-Email Maintainer**, **Official Registry Vacuum**. | `ASI03`, `ASI04`, `ASI05`, `ASI07`, `ASI09` / `MCP01:2025`, `MCP04:2025`, `MCP05:2025`, `MCP09:2025` |
| **V2 (Secondary)** | **External Perimeter, DNS-AID & OAuth Hygiene** | Queries DoH (`do=1`) for IETF DNS-AID (`_agent.<domain>`, `_mcp.<domain>` `SVCB`/`TXT`/`SRV`) & DNSSEC `AD` bit; multi-provider CT (CertSpotter + `crt.sh` fallback) + live TLS SANs for `mcp.*`/`agents.*`; RFC 9728 (`/.well-known/oauth-protected-resource` + `WWW-Authenticate` `resource_metadata`), **Broad OAuth Scope Declaration**, and **Cross-Domain Perimeter Drift** (suppressing legacy 400 gateways, HTML SPAs, and multi-tenant SSO portals). | `ASI03`, `ASI04`, `ASI07` / `MCP02:2025`, `MCP07:2025`, `MCP09:2025` |
| **V3 (Silent Sub-Check)** | **Active Lookalike Infrastructure** | Silently suppresses domain parking, GoDaddy/Afternic landers, Cloudflare HTTP 523 squatters, defensive registrations, and generic HTTP 200 prose. Emits findings *only* for **Active Lookalike Agent Endpoint** (`/.well-known/mcp.json` or live JSON-RPC/SSE `/mcp`) or **Phishing-Warning Lookalike Domain** (HTTP 403/451 third-party interstitials). | `ASI04`, `ASI07`, `ASI09` / `MCP04:2025`, `MCP09:2025` |

---

## Single-File CISO HTML Report

Running `--html report.html` generates a completely self-contained, print-friendly executive HTML report (zero external CDN scripts, stylesheets, or fonts) designed to be absorbed by a Fortune 500 CISO in 30 seconds:
- Dual-Axis Executive Hero (First-Party Control Posture SVG ring + External Threat Pressure severity gauge) and 2D Action Posture banner
- 6-Control First-Party Posture Breakdown checklist (or Baseline Readiness panel for `N/A` zero-footprint targets)
- 30-second Executive Brief & Owner-Split Prioritized Action Plan (context-aware recommendations)
- Axis-grouped Findings (`First-Party Control Gaps` vs. `External Ecosystem Threats`) with OWASP ASI/MCP badges and collapsible raw verifiable JSON evidence
- Official-first MCP Registry provenance map, npm/PyPI package table (with co-maintainer email clarity), and DNS-AID/RFC 9728 posture table

---

## Empirical Study: *State of External Agentic Exposure 2027*

An anonymized passive baseline across **100 public brands** (50 Traditional Fortune/S&P 500 Enterprises + 50 SaaS, Fintech, Cloud, Cybersecurity & AI brands) is included in:
- Anonymized dataset: [`datasets/study_2027_anonymized.json`](datasets/study_2027_anonymized.json)
- Statistical summary: [`docs/state_of_external_agentic_exposure_2027.md`](docs/state_of_external_agentic_exposure_2027.md)

**Key Verified Findings (N=100, `2-axis-v1`):**
- **2-Axis Distribution:** `58` brands graded on Axis 1 (Mean Control Posture `48.8` / Median `51.5`; `A=4, B=13, C=9, D=11, F=21`) and `42` `N/A Baseline` (`0` inflated Grade A's). Axis 2 External Threat Pressure across all `100` brands: Mean `24.7` / Median `26.0` (`Critical=1, High=20, Moderate=31, Low=4, None=44`).
- **Official Registry Vacuum:** `58%` (`58/100`) have an external MCP ecosystem footprint (`20%` Fortune 500 vs. `96%` Tech/SaaS/AI), yet only `25%` (`25/100`) have an officially domain-anchored entry (`6%` Fortune 500 vs. `44%` Tech). **`33%` of all brands** (`56.9%` of brands with MCP footprint; `70.0%` of Fortune 500 brands with MCP activity) sit in an Official Registry Vacuum.
- **Unverified 3P Proxies & Free-Email Packages:** `39%` (`14%` Fortune 500, `64%` Tech; `92.9%` Enterprise SaaS) have unverified third-party hosted proxies claiming their brand (`1%` critical URL-Path Token Exposure); `50%` (`10%` Fortune 500, `90%` Tech; `100%` AI & Data Platforms) have unverified packages maintained via free-email accounts.
- **Live MCP & Open DNS Standards:** `29%` (`29/100`) operate live first-party `mcp.*` endpoints, of which `13.8%` (`4/29`, including `2/2` Fortune 500 live endpoints) lack RFC 9728 metadata. **`0%` (`0/100`)** publish IETF DNS-AID (`_agent`/`_mcp`) records; only `18%` (`18/100`) validate apex DNSSEC (`AD=true`). `3%` (`3/100`) triggered confirmed HTTP 403 phishing-warning lookalike interstitials (`0` parking/523 false positives).

All target domains, brand names, and sensitive live misconfiguration URLs are stripped from the public study in accordance with our responsible disclosure policy.

---

## Development & Testing

```bash
uv run --python 3.12 pytest -v
```

## Responsible Disclosure & Passive-Only Ethics

`agent-perimeter` is strictly 100% passive and read-only, uses strictly factual neutral technical labels, and never runs intrusive scans, brute-forcing, or `tools/call` against third-party servers. Read [SECURITY.md](SECURITY.md) before running cohort studies or reporting findings.

## License

Apache-2.0 — see [LICENSE](LICENSE).
