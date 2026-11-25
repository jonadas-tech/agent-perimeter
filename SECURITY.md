# Security & Responsible Disclosure Policy

`agentic-perimeter` is designed strictly as a **100% passive, read-only** external attack surface measurement and defensive audit tool.

## Passive-Only Operating Guarantees

`agentic-perimeter` exclusively performs:
- Public DNS-over-HTTPS queries (`A`, `AAAA`, `CNAME`, `NS`, `SVCB`, `TXT`, `SRV`, and DNSSEC `AD` bit checks).
- Public Certificate Transparency lookups (CertSpotter API / bounded `crt.sh` fallback) and standard port-443 TLS leaf certificate inspection.
- Polite, rate-limited HTTP `GET` requests on standard public discovery paths (`/.well-known/oauth-protected-resource`, `/.well-known/mcp.json`, `/.well-known/agent-card.json`, `/.well-known/agent.json`, `/mcp`) using an honest `User-Agent`.
- Read-only queries to public package and MCP registries (Official MCP Registry v0.1, npm Registry API, PyPI JSON API, GitHub public REST API).

`agentic-perimeter` **never** performs:
- Port scanning, brute-forcing of private paths, credential stuffing, or authentication bypass attempts.
- Intrusive MCP RPC calls (`tools/call`) or payload execution against third-party servers.
- Unthrottled scraping or denial-of-service traffic.

## Responsible Disclosure Policy

- **Empirical Cohort Studies:** Any published benchmark dataset (such as *State of External Agentic Exposure 2027*) strips target domain/brand identifiers and sensitive live misconfiguration URLs, publishing only anonymized cohort records and aggregate statistics.
- **Live Misconfigurations:** If an audit uncovers a live security misconfiguration affecting a specific organization, we follow coordinated disclosure best practices (minimum 90-day disclosure window via the organization's `security.txt`, bug bounty program, or PSIRT contact) prior to any non-anonymized public discussion.
- **Neutral Technical Labels:** Tool outputs describe verifiable provenance facts (for example, *Unverified 3rd-Party Hosted Proxy*, *URL-Path Token Exposure*, or *Unscoped Package / Free-Email Maintainer*) and never assert malicious intent by commercial aggregators or community maintainers.

## Reporting Security Issues in `agentic-perimeter`

If you discover a vulnerability in `agentic-perimeter` itself (such as HTML injection in report rendering, unsafe parsing, or SSRF/redirect handling bugs), please report it privately via GitHub Security Advisories on this repository before opening a public issue.
