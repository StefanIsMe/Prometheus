# Changelog

All notable changes to Prometheus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Expanded vulnerability coverage beyond the v1 seven classes.
- Stable CI workflow with lint, type-check, and test jobs.
- Pluggable sandbox backends beyond Docker.
- Optional web UI companion.

## [1.0.0] - 2026-06-15

### Added
- **Local-only build mode** — Prometheus no longer requires an external
  network for telemetry, account bootstrap, or model provisioning at
  startup (`prometheus/telemetry/` PostHog and Scarf are no-op stubs).
- **Scope guardrail** — four-pattern allowlist (bare domain, `*.example.com`,
  exact, CIDR) plus `re:` regex, with deny-wins, default-deny, and
  suffix-confusion protection. Refuses to dispatch any out-of-scope URL
  during PoC validation. Ported from
  [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter).
- **Engagement folder scaffold** — per-target directory at
  `~/.prometheus/engagements/<domain>/` with `scope.md`, `findings/`,
  `evidence/`, `state.json`, `engine.log`, and `runs/<run_id>/`. Ported
  from Claude-BugHunter.
- **7-Question Gate** — PASS / KILL_Q{n} / DOWNGRADE_Q{n} / CHAIN_REQUIRED
  outcomes with 5-min and 30-min time-boxes, ported from Claude-BugHunter.
- **Always-Rejected matrix** — 20+ reject rules for findings that must
  not be reported (e.g. missing CSP alone, internal hostname alone),
  ported from Claude-BugHunter.
- **Conditionally-Valid chain table** — 12+ chain patterns (e.g. open
  redirect + OAuth = ATO), ported from Claude-BugHunter.
- **Recon framework** — SPA-aware deterministic recon: seed HTML fetch,
  same-origin JS bundle download, regex-mined API routes, secret
  scanning, endpoint classification. Ported from Claude-BugHunter.
- **Evidence-hygiene skill** — ported from Claude-BugHunter.
- **Seven hunt playbooks** — `hunt-idor`, `hunt-auth-bypass`,
  `hunt-account-enumeration`, `hunt-ssrf`, `hunt-cors`,
  `hunt-exposed-unauthenticated`, `hunt-source-map`, each in the
  Prometheus 12-section format and adapted from the corresponding
  Claude-BugHunter playbook.
- **9-stage pipeline shape** — Discovery & Modeling → Deep Dive &
  Verification → Synthesis, Chaining & Reporting, derived from
  [Visa VVAH](https://github.com/visa/visa-vulnerability-agentic-harness).
- **N-run deterministic LLM voting** — runs the deep-dive stage N times
  (default 3) at temperature > 0; keeps findings passing
  `vote_threshold` (default 2/3). Schema derived from VVAH.
- **`run_manifest.json`** — config hash, prompt hash, model IDs, and
  per-stage durations, VVAH-derived schema.
- **SARIF 2.1.0 emission** — `prometheus/report/` outputs SARIF
  alongside the Markdown report. VVAH-derived.
- **Threat-model stage** — STRIDE / OWASP / MASVS / CWE-narrowed attack
  surface map before deep-dive. VVAH-derived.
- **Per-stage model routing** — Haiku for threat model, Sonnet for
  deep-dive, Opus for adversarial verify.
- **Penetration Task Graph (PTG)** — phase-based pentest workflow
  planner (RECON, FINGERPRINT, THREAT_INTEL, VULNERABILITY_SCAN,
  EXPLOITATION), inspired by VulnBot (arXiv:2501.13411).
- **Chain linker** — proposes chains across findings on the same
  `(domain, asset_class)`.
- **Headless mode (`-n` / `--non-interactive`)** — prints real-time
  findings and a final report; non-zero exit code on validated
  vulnerabilities, suitable for CI.
- **GitHub Actions integration** — `quickstart.mdx` and the README ship
  a working `.github/workflows` example.
- **Eval harness** — skills-on vs. skills-off ablation against Juice
  Shop and PortSwigger Academy. Ported from Claude-BugHunter.
- **Package metadata dunders** — `__version__`, `__license__`,
  `__author__`, `__author_email__`, `__copyright__`, `__url__` exposed
  from `prometheus/__init__.py`.
- **Project metadata** — `AUTHORS`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`,
  and `DISCLAIMER.md` added at the repo root.

### Changed
- **Project renamed from Strix to Prometheus** — all code, scripts,
  CI, prompts, and docs updated. See commit history prior to v1.0.0
  for the rename work.
- **License switched from Apache-2.0 to MIT** — `LICENSE` replaced,
  `pyproject.toml` license field updated to SPDX, classifiers updated
  to `License :: OSI Approved :: MIT License`. Author changed to
  Stefan Carter (`<stefan@withapurpose.co>`).
- **Telemetry is no-op** — PostHog and Scarf modules in
  `prometheus/telemetry/` are stubs that make no network calls.

### Removed
- Upstream narrative comments and module/helper docstrings stripped for
  clarity. Per-file attribution is preserved at the top of the
  ported-from-upstream files.
- "Prescriptive guidance" placeholder in the image-rejection skill
  dropped.
- `prom-rl` / `/loop` RL-loop scaffolding removed from the public
  tree; the `prometheus_runs/` directory and `prometheus.db` file at
  the repo root are no longer committed (`.gitignore` already
  excluded them).

### Fixed
- **5-phase audit remediation** — 262 tests pass at v1.0.0.
- ENV-variable casing bug (`prometheus_LLM` → `PROMETHEUS_LLM`) in
  the README and CONTRIBUTING.md.
- Renamed `strix.log` → `prometheus.log`.
- Replay and review-escalation regression tests added; circuit-breaker
  and event-sink tests added; LLM-budget preflight tests added; PoC
  validation safe-execution tests added.

### Security
- See [DISCLAIMER.md](DISCLAIMER.md) for the full limitation of
  liability and authorized-use terms. By using Prometheus you accept
  that the author and contributors are not liable for any damages
  arising from your use of the software.

[Unreleased]: https://github.com/StefanIsMe/Prometheus/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/StefanIsMe/Prometheus/releases/tag/v1.0.0
