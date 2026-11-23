# State of External Agentic Exposure 2027 — Anonymized Empirical Summary

**Dataset Size:** 100 public brands (50 Traditional Fortune/S&P 500 + 50 SaaS/Fintech/Cloud/AI)  
**Scan Window:** `2026-11-21T12:02:08Z` to `2026-11-21T12:13:13Z` (`665.25s`)  
**Tool & Scoring Model:** `agent-perimeter` v0.1.0 · `2-axis-v1` (100% passive, read-only public APIs, DoH, CT/TLS SAN)  
**Axis 1 — First-Party Control Posture (Graded N=58; Baseline N/A=42):** Mean `48.8` / Median `51.5` (Grades: A=4, B=13, C=9, D=11, F=21, N/A=42)  
**Axis 2 — External Ecosystem Threat Pressure (All N=100):** Mean `24.7` / Median `26.0` (Levels: Critical=1, High=20, Moderate=31, Low=4, None=44)

> **Responsible Disclosure & Neutrality Notice:** All target domains, brand names, and live misconfiguration URLs have been stripped and replaced with anonymized cohort identifiers (ENT-xxx, TECH-xxx) in accordance with responsible disclosure policy.

---

## 1. Cohort Comparison: Traditional Enterprise vs. SaaS / Fintech / AI

| Metric | All Brands (N=100) | Traditional Fortune/S&P 500 (N=50) | SaaS / Fintech / Cloud / AI (N=50) |
|---|---:|---:|---:|
| Any external MCP ecosystem footprint | 58 (58.0%) | 10 (20.0%) | 48 (96.0%) |
| Official domain-anchored MCP Registry entry | 25 (25.0%) | 3 (6.0%) | 22 (44.0%) |
| **Official Registry Vacuum** (0 official + >=1 unverified 3P) | 33 (33.0%) | 7 (14.0%) | 26 (52.0%) |
| **Unverified 3rd-Party Hosted MCP Proxy** claiming brand | 39 (39.0%) | 7 (14.0%) | 32 (64.0%) |
| **URL-Path Token Exposure** in 3P proxy template | 1 (1.0%) | 0 (0.0%) | 1 (2.0%) |
| Unverified npm or PyPI MCP package claiming brand | 54 (54.0%) | 7 (14.0%) | 47 (94.0%) |
| **Free-Email Maintainer** on unverified MCP package | 50 (50.0%) | 5 (10.0%) | 45 (90.0%) |
| Live first-party `mcp.*` / `agents.*` endpoint | 29 (29.0%) | 2 (4.0%) | 27 (54.0%) |
| Missing RFC 9728 metadata (among live MCP endpoints) | 4/29 (13.8%) | 2/2 (100.0%) | 2/27 (7.4%) |
| Broad OAuth Scope Declaration | 6 (6.0%) | 0 (0.0%) | 6 (12.0%) |
| Cross-Domain Perimeter Drift | 3 (3.0%) | 0 (0.0%) | 3 (6.0%) |
| Apex DNSSEC validated (`AD=true`) | 18 (18.0%) | 6 (12.0%) | 12 (24.0%) |
| IETF DNS-AID (`_agent` / `_mcp` SVCB/TXT) present | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Active Lookalike Agent Endpoint (V3 high-signal) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| Phishing-Warning Lookalike Domain (V3 high-signal) | 3 (3.0%) | 1 (2.0%) | 2 (4.0%) |

## 2. 2-Axis Action Posture Breakdown

| 2-Axis Action Posture | All Brands (N=100) | Traditional Fortune/S&P 500 (N=50) | SaaS / Fintech / Cloud / AI (N=50) |
|---|---:|---:|---:|
| **Urgent Remediation** | 11 (11.0%) | 1 (2.0%) | 10 (20.0%) |
| **Action Required** | 19 (19.0%) | 5 (10.0%) | 14 (28.0%) |
| **Priority Hardening** | 4 (4.0%) | 0 (0.0%) | 4 (8.0%) |
| **Proactive Hardening** | 2 (2.0%) | 1 (2.0%) | 1 (2.0%) |
| **Hardening & Monitoring** | 3 (3.0%) | 0 (0.0%) | 3 (6.0%) |
| **Targeted Hardening** | 2 (2.0%) | 2 (4.0%) | 0 (0.0%) |
| **Active Defense** | 6 (6.0%) | 0 (0.0%) | 6 (12.0%) |
| **Active Monitoring** | 8 (8.0%) | 0 (0.0%) | 8 (16.0%) |
| **Well-Positioned** | 3 (3.0%) | 1 (2.0%) | 2 (4.0%) |
| **Brand Protection Alert** | 1 (1.0%) | 1 (2.0%) | 0 (0.0%) |
| **Baseline — Monitor** | 41 (41.0%) | 39 (78.0%) | 2 (4.0%) |

## 3. OWASP Agentic Top 10 (2026) & OWASP MCP Top 10 (2025) Prevalence

| OWASP Mapping | Affected Brands (N=100) | Prevalence |
|---|---:|---:|
| `ASI03` | 11 | 11.0% |
| `ASI04` | 56 | 56.0% |
| `ASI05` | 50 | 50.0% |
| `ASI07` | 46 | 46.0% |
| `ASI09` | 45 | 45.0% |
| `MCP01:2025` | 1 | 1.0% |
| `MCP02:2025` | 6 | 6.0% |
| `MCP04:2025` | 56 | 56.0% |
| `MCP05:2025` | 50 | 50.0% |
| `MCP07:2025` | 4 | 4.0% |
| `MCP09:2025` | 51 | 51.0% |

## 4. Breakdown by Industry Sector

| Sector | Graded / Total | Mean Posture (Graded) | Mean Threat Pressure | Official Registry | Registry Vacuum | 3P Hosted Proxy | Free-Email Pkg | DNSSEC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AI & Data Platforms | 8/8 | 52.8 | 41.2 | 37.5% | 62.5% | 50.0% | 100.0% | 25.0% |
| Aerospace & Auto | 1/3 | 0.0 | 4.0 | 0.0% | 33.3% | 0.0% | 0.0% | 0.0% |
| Banking & Finance | 3/13 | 51.3 | 5.0 | 15.4% | 7.7% | 7.7% | 7.7% | 15.4% |
| Cloud & DevTools | 13/13 | 75.3 | 41.8 | 84.6% | 15.4% | 53.8% | 92.3% | 15.4% |
| Commerce & Platforms | 4/5 | 13.0 | 45.0 | 0.0% | 80.0% | 80.0% | 80.0% | 20.0% |
| Cybersecurity | 3/3 | 67.0 | 25.7 | 66.7% | 33.3% | 0.0% | 66.7% | 33.3% |
| Energy & Industrial | 1/7 | 66.0 | 2.9 | 14.3% | 0.0% | 14.3% | 0.0% | 28.6% |
| Enterprise SaaS | 14/14 | 46.6 | 49.5 | 28.6% | 71.4% | 92.9% | 92.9% | 35.7% |
| Fintech & Payments | 6/7 | 50.8 | 43.7 | 28.6% | 57.1% | 57.1% | 85.7% | 14.3% |
| Healthcare & Pharma | 0/6 | N/A | 0.0 | 0.0% | 0.0% | 0.0% | 0.0% | 16.7% |
| Insurance | 0/3 | N/A | 0.0 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Logistics & Travel | 0/3 | N/A | 0.0 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Retail & Consumer | 4/11 | 0.0 | 14.5 | 0.0% | 36.4% | 36.4% | 27.3% | 0.0% |
| Telecom & Media | 1/4 | 0.0 | 10.0 | 0.0% | 25.0% | 25.0% | 25.0% | 25.0% |

## 5. Full Unverified Package Static Census (N=632 / 642 Inspected In Memory)

Beyond registry and perimeter metadata, we performed a **100% passive, read-only in-memory static inspection** (`io.BytesIO`, <=5 MB archive cap, zero package execution) across all **642 unique unverified brand-named MCP packages** (`529` npm + `113` PyPI) discovered across the Top-100 cohort. **632 packages (`98.4%`: `520` npm, `112` PyPI)** were inspected in memory; `10` exceeded the `5 MB` archive cap (`8.3 MB`–`78.3 MB`, primarily bundled native Go/Rust binaries). Full anonymized metrics are stored in [`datasets/static_census_2027_anonymized.json`](../datasets/static_census_2027_anonymized.json).

| Passive Static Signal (`N=632` Inspected Packages) | Count | Prevalence | Significance |
|---|---:|---:|---|
| **Missing source repository URL** in package metadata | **150** | **23.7%** | Nearly 1 in 4 unverified brand-named MCP packages cannot be traced to a public source repository |
| **Lifecycle scripts declared** (`preinstall`/`install`/`postinstall`/`prepare`) | **117** | **18.5%** | `31` (`4.9%`) non-standard hooks; `3` `postinstall` remote native binary downloaders (`1` with zero SHA-256 verification) |
| **Shell / subprocess execution** (`child_process` / `subprocess`) | **109** | **17.2%** | Local command execution surface inside unverified MCP wrappers |
| **References local AI agent config files** (`.cursor/mcp.json`, `claude_desktop_config.json`, `.codex/config.toml`) | **26** | **4.1%** | Direct interaction with developer agent configuration paths |
| **Dormant placeholder stubs** (`coming-soon` / `89-byte` stubs) | **22** | **3.5%** | Latent namespace-squat inventory spanning `13` Top-100 brands |
| **Unrelated CLI `bin` name registration** | **11** | **1.7%** | Includes cross-brand CLI binary shadowing in `PATH` |
| **Anti-bot / TLS evasion libraries** (`Patchright`, `curl_cffi` Chrome TLS impersonation) | **6** | **0.9%** | Wrappers automating consumer/enterprise web portals behind bot management |
| **Stealth session-cookie / admin-approval bypass** (`xoxc`/`xoxd`) | **5** | **0.8%** | Includes a `229k+` dl/mo unscoped wrapper explicitly bypassing workspace admin approval |
| **Verified hidden prompt-injection / Unicode Tag payloads** | **0** | **0.0%** | Current real-world risk is classical supply-chain & governance failure, not covert tool-description prompt injection |

**Maintainer Blast-Radius Concentration:** **`29` individual maintainer accounts** each publish unverified MCP packages targeting **3 to 23 distinct Top-100 brands**. The top two accounts alone maintain `24` packages across `23` Top-100 brands and `18` packages across `18` Top-100 brands, illustrating that compromise of a single third-party maintainer account cascades across dozens of enterprise brands simultaneously. Separately, **`5` of `50` Tech/SaaS brands (`10.0%`)** already have exact unscoped `mcp-server-<brand>` names replaced with npm Security `0.0.1-security` holding packages.

---

## 6. Methodology Summary (Passive-Only, 2-Axis Risk Model)

- **Scoring (`2-axis-v1`):** Separates **First-Party Control Posture** (0–100, Grade `A–F` across applicable controls `C1–C6`: Official Registry, Official Scoped Packages, RFC 9728 coverage, Least-Privilege OAuth Scopes, Domain Boundary Consistency, and DNSSEC/DNS-AID; `N/A Baseline` for zero-footprint brands) from **External Ecosystem Threat Pressure** (0–100, `None`–`Critical` across `T1–T6`: URL-Path Token Exposure, Unverified 3P Proxies, Free-Email Maintainer Collisions, Unverified Packages, Active Lookalike Agent Endpoints, and Phishing-Warning Lookalikes).
- **V1 (MCP Supply-Chain Provenance):** Queries `registry.modelcontextprotocol.io/v0.1/servers` (broad + targeted reverse-DNS anchor queries), npm Registry API, PyPI JSON API, and GitHub REST API. Anchors official assets using reverse-DNS prefixes, verified sibling domains, GitHub org `blog`/`email` verification, and cross-registry npm/PyPI maintainer email anchoring. Strips hosting-platform prefixes (`io.github.*`, `app.vercel.*`, `dev.workers.*`), skips unpublished tombstones, isolates `0.0.1-security` holding packages, and applies homonym/generator filters.
- **V2 (External Perimeter, DNS-AID & OAuth):** Queries Google/Cloudflare DoH (`do=1` for DNSSEC `AD` bit) for `_agent.<domain>` and `_mcp.<domain>` SVCB/TXT/SRV records, Certificate Transparency (CertSpotter primary + `crt.sh` fallback) + live TLS SAN inspection for `mcp.*` / `agents.*`, and passive HTTP GET on RFC 9728 (`/.well-known/oauth-protected-resource`) and standard `.well-known` discovery documents.
- **V3 (Silent Active Lookalike Sub-Check):** Silently suppresses domain parking, GoDaddy/Afternic/Confluence landers, Cloudflare HTTP 523 squatters, and defensive brand registrations; flags only confirmed active `/mcp` / `.well-known` agent endpoints or HTTP 403/451 third-party phishing warning interstitials.
