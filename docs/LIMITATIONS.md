# Limitations & false positives

`agentic-perimeter` classifies public metadata with heuristics. This page lists what those heuristics can get wrong, both for single-domain audits and for the November 2026 baseline study (*State of External Agentic Exposure*; files keep the original "2027" identifier). The same notes appear in the method section of the [narrative study](https://www.jonadas.com/writing/research/state-of-external-agentic-exposure-2026-baseline).

If a result is wrong for something you own or maintain, please [report a false positive](https://github.com/jonadas-tech/agentic-perimeter/issues/new?template=false_positive.yml).

## Classification

- **No hand-labelled precision estimate yet.** The "official" vs. "unverified" split has not been checked against a manually labelled sample of the study data. The Phase 0 pilot found and fixed anchoring errors on several brands before the full scan, which is evidence that errors exist, not a measured rate. A precision estimate on a random sample of classified entries is planned (see the TODO in the narrative study).
- **"Unverified" is not "malicious".** It means the entry or package could not be anchored to the brand's verified domains (reverse-DNS registry namespace, maintainer email on the brand's domain, or a GitHub organization verified for that domain). Many unverified packages are legitimate community work.
- **Official packages can be classified as unverified.** An employee who publishes an official package from a personal address, or an organization whose GitHub profile does not list its domain, will not be anchored.
- **Free-email maintainer is a weak signal.** Many legitimate maintainers publish from Gmail or Outlook. It is reported as context for supply-chain pressure, not as evidence of impersonation.
- **Brand matching is name-based.** Brands whose names collide with common words or programming terms produce noise; homonym filters reduce it but cannot remove it. The study sample deliberately excluded short or ambiguous brand names for this reason.

## Coverage

- **Counts are floors.** npm search returns a bounded number of results per brand (the top 25, plus six exact high-risk names such as `mcp-server-<brand>`); the registry is paged to a fixed limit. Real counts are likely higher.
- **Single snapshot.** The study reflects one scan (21 November 2026, `v0.1.0`) and one package census (23 November 2026). The ecosystem changes weekly.
- **Static package checks are signature-based.** The census looks for invisible Unicode Tag characters and known prompt-injection phrasings in package files. It cannot detect novel phrasing, obfuscated payloads, or tool descriptions that a remote server serves at runtime (including hosted proxies, which are never called). "Zero prompt injection found" is a statement about those signatures only.
- **Archives over 5 MB are skipped** (10 of 642 packages in the census, mostly bundled native binaries).

## Study design

- **Calibration brands are inside the sample.** The 20 brands used to tune the anchoring rules in Phase 0 are part of the 50-brand technology cohort. Precision may be higher for them than for the other 80 brands (overfitting risk).
- **Curated, not random.** The 100 brands are household names chosen for sector coverage; results describe well-known, distinctly named brands, not companies in general.
- **Small denominators.** Some comparisons rest on very few cases (for example, only 2 traditional enterprises run a live `mcp.*` endpoint, and only 10 have any MCP footprint). Read cohort percentages together with their counts.

## Anonymization

- **The brand list is public** (`datasets/top100_brands.json`), so anonymity protects who authored a per-brand verdict, not whether someone can re-run the scan.
- **Record IDs are assigned in random order** and sectors with fewer than 5 brands are merged (`study.MIN_CELL_SIZE`). Sector means of the control-posture score are suppressed when fewer than 5 brands in that sector are graded.
- **Homogeneous cells still leak.** When every member of a sector shares a value (for example, a sector where no brand has an official registry entry), the published rate reveals that value for each member. Sector tables should be read as aggregates and not repeated as statements about named companies.
