<div align="center">

# Prometheus

### Open-source AI agents for authorized security testing and bug-bounty validation.

<br/>

<a href="https://github.com/StefanIsMe/Prometheus/blob/main/LICENSE"><img src="https://img.shields.io/github/license/StefanIsMe/Prometheus?style=flat-square" alt="License: MIT"></a>
<a href="https://github.com/StefanIsMe/Prometheus/stargazers"><img src="https://img.shields.io/github/stars/StefanIsMe/Prometheus?style=flat-square" alt="GitHub Stars"></a>
<a href="https://pypi.org/project/prometheus-agent/"><img src="https://img.shields.io/pypi/v/prometheus-agent?style=flat-square" alt="PyPI Version"></a>
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square" alt="Python 3.12+"></a>
<img src="https://img.shields.io/badge/status-alpha-orange?style=flat-square" alt="Status: Alpha">

<br/>

[Quick Start](#-quick-start) · [Documentation](docs/) · [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security](SECURITY.md) · [Disclaimer](DISCLAIMER.md) · [Changelog](CHANGELOG.md) · [Authors](AUTHORS)

</div>

> [!WARNING]
> **Prometheus is an active security-testing tool.** It probes, mutates, and
> (in a sandbox) executes code against the targets you point it at. **Only
> run it against systems you own or have explicit, written authorization to
> test.** See [DISCLAIMER.md](DISCLAIMER.md) for the full limitation of
> liability and authorized-use terms. By using Prometheus you agree to them.

---

## What is Prometheus?

Prometheus is a CLI agent that takes a target — a local directory, a Git
repository, or a live URL — and runs an **authorized security test** against
it. It is built around a 9-stage pipeline (Discovery & Modeling → Deep Dive
& Verification → Synthesis, Chaining & Reporting), and uses
**multi-agent orchestration** with N-run LLM voting to keep the false-positive
rate down on the way to validated, proof-of-concept-backed findings.

The v1 release focuses on the seven vulnerability classes most useful to
bug-bounty and external-attack-surface work:

- **IDOR / BOLA** — object-level authorization failures
- **Auth bypass** — protected actions reachable without a valid session
- **Account enumeration** — stable differential responses
- **SSRF** — server-side request forgery with OOB or internal-reach proof
- **CORS misconfiguration** — readable protected responses or state-changing CSRF
- **Exposed unauthenticated** — sensitive endpoints or privileged actions reachable
- **Source map / JS-bundle leak** — code disclosure that chains to an exploit

Findings are validated by an **adversarial verification stage** with a
different model tier than the deep-dive, gated by a **7-Question
triage gate** (PASS / KILL / DOWNGRADE / CHAIN_REQUIRED), filtered against
an **Always-Rejected matrix** (≥20 reject rules) and a
**Conditionally-Valid chain table** (≥12 chain patterns), and finally
de-duplicated and chained before being written to the report.

The full pipeline, gates, and playbooks are documented under
[prometheus/playbooks/](prometheus/playbooks/) and
[prometheus/skills/](prometheus/skills/).

---

## Built on the Shoulders Of

Prometheus is a hard fork of [Strix](https://github.com/usestrix/strix)
(Apache-2.0), extended with two further open-source projects:

- **[Claude-BugHunter (CBH)](https://github.com/elementalsouls/Claude-BugHunter)**
  by [Sachin Sharma (@ElementalSouls)](https://github.com/elementalsouls) —
  MIT. Contributed the **engagement-folder model**, the **scope guardrail**
  with suffix-confusion protection, the **7-Question Gate**, the
  **Always-Rejected** and **Conditionally-Valid** matrices, the
  **evidence-hygiene skill**, and the **seven hunt playbooks**.
- **[Visa Vulnerability Agentic Harness (VVAH)](https://github.com/visa/visa-vulnerability-agentic-harness)**
  by [Visa, Inc.](https://github.com/visa) — Apache-2.0. Contributed the
  **9-stage pipeline shape**, the **threat-model stage**, the **N-run
  deterministic LLM voting** for false-positive reduction, the
  **`run_manifest.json` schema**, and **SARIF 2.1.0** emission.
- **[Strix](https://github.com/usestrix/strix)** by the Strix
  contributors — Apache-2.0. Contributed the **original agent runtime**,
  **CLI/TUI**, **sandbox lifecycle**, **multi-agent orchestration**, the
  HTTP proxy, browser automation, terminal, Python runtime, and knowledge
  store that Prometheus was forked and renamed from.

Per-file attribution is preserved in the module docstrings under
`prometheus/` and the playbook headers under `prometheus/playbooks/`. The
full attribution is in [AUTHORS](AUTHORS).

---

## 🚀 Quick Start

**Prerequisites:**

- Python 3.12+
- Docker (running) — used to sandbox probe execution
- An LLM API key from any [supported provider](docs/llm-providers/)

### Install & first scan

```bash
# Install Prometheus
curl -sSL https://raw.githubusercontent.com/StefanIsMe/Prometheus/main/scripts/install.sh | bash

# Configure your AI provider
export PROMETHEUS_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
prometheus --target ./app-directory
```

> [!NOTE]
> First run pulls the sandbox Docker image. Run artifacts go to
> `prometheus_runs/<run-name>/`; the canonical knowledge store is at
> `~/.prometheus/prometheus.db`.

For pipx / uv installs, more target types, and the full
provider matrix, see [`docs/quickstart.mdx`](docs/quickstart.mdx).

---

## ✨ Features

### Agentic security toolkit

Every scan starts a sandboxed runtime that exposes the agent a complete
hacker toolkit:

- **Full HTTP proxy** — request/response capture, replay, and mutation
  (via Caido SDK)
- **Browser automation** — multi-tab, multi-page XSS / CSRF / auth-flow
  testing (via Playwright)
- **Terminal** — interactive shells inside the sandbox
- **Python runtime** — custom exploit development and validation
- **Reconnaissance** — SPA-aware seed-HTML fetch, JS-bundle download,
  regex-mined API routes, secret scanning, endpoint classification
- **Code analysis** — static and dynamic, source-aware when scanning a
  local directory
- **Knowledge store** — durable, queryable findings and evidence
  (SQLite at `~/.prometheus/prometheus.db`)

### Graph of agents

Multi-agent orchestration: specialized agents per attack surface,
parallel execution, dynamic coordination. The Penetration Task Graph
(PTG) is a phase-based pentest workflow (RECON → FINGERPRINT →
THREAT_INTEL → VULNERABILITY_SCAN → EXPLOITATION) inspired by VulnBot
(arXiv:2501.13411).

### Adversarial verification & gating

Findings are not reported as-is. They pass through:

1. **N-run LLM voting** (default 3 runs at temperature > 0; default
   threshold 2/3) to filter flaky positives.
2. **Adversarial verification** by a separate role with a different
   model tier than the deep-dive.
3. **7-Question Gate** — PASS / KILL_Q{n} / DOWNGRADE_Q{n} / CHAIN_REQUIRED
   with 5-min and 30-min time-boxes.
4. **Always-Rejected matrix** — 20+ reject rules for findings that
   must not be reported (e.g. missing CSP alone, internal hostname
   alone).
5. **Conditionally-Valid chain table** — 12+ chain patterns
   (e.g. open redirect + OAuth = ATO).
6. **Chain linker** — proposes chains across findings on the same
   `(domain, asset_class)`.

### Reporting

Versioned report artifacts (`report_markdown`, `bugcrowd_json`,
`h1_markdown`, `poc_script`, `evidence_bundle`) plus **SARIF 2.1.0**
output. HackerOne and Bugcrowd drafts, Bugcrowd VRT classification,
CVE + CWE validation, and duplicate detection. **No auto-submit** —
human review of every report is mandatory.

### Modes

- **Interactive TUI** (Textual)
- **Headless** (`-n` / `--non-interactive`) — prints real-time findings
  and a final report; non-zero exit on validated vulnerabilities
- **PR diff-scope** (`--scope-mode diff --diff-base origin/main`) for
  CI pull-request runs
- **GitHub Actions** — see the example below or
  [`docs/integrations/github-actions.mdx`](docs/integrations/github-actions.mdx)

---

## Usage examples

```bash
# Local codebase
prometheus --target ./app-directory

# Public GitHub repo
prometheus --target https://github.com/org/repo

# Live web app
prometheus --target https://your-app.com

# Grey-box / authenticated
prometheus --target https://your-app.com --instruction "test as user:pass"

# Multi-target
prometheus -t https://github.com/org/app -t https://your-app.com

# Custom rules of engagement
prometheus --target api.your-app.com --instruction-file ./instruction.md

# PR diff-scope in CI
prometheus -n --target ./ --scope-mode diff --diff-base origin/main
```

### CI / GitHub Actions

```yaml
name: prometheus-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Prometheus
        run: curl -sSL https://raw.githubusercontent.com/StefanIsMe/Prometheus/main/scripts/install.sh | bash

      - name: Run Prometheus
        env:
          PROMETHEUS_LLM: ${{ secrets.PROMETHEUS_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: prometheus -n -t ./
```

> [!TIP]
> Prometheus automatically scopes CI pull-request runs to changed files
> when invoked with `-n` and a target of `./`. If diff-scope cannot
> resolve, make sure checkout uses full history
> (`fetch-depth: 0`) or pass `--diff-base` explicitly.

### Configuration

```bash
export PROMETHEUS_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="https://api.openai.com/v1"  # for local models, Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"          # for search
export PROMETHEUS_REASONING_EFFORT="high"         # high | medium | low
```

Configuration is persisted to `~/.prometheus/cli-config.json` so it
does not need to be re-entered on every run.

**Recommended models:** `openai/gpt-5.4`, `anthropic/claude-sonnet-4-6`,
`vertex_ai/gemini-3-pro-preview`. See [`docs/llm-providers/`](docs/llm-providers/)
for the full list (Anthropic, OpenAI, Google, Vertex AI, Bedrock, Azure,
local via Ollama/LMStudio).

---

## Project layout

```
prometheus/
├── agents/         # Sandbox agent factory + system prompts
├── chains/         # Chain templates (reserved)
├── config/         # Settings, LLM config, Hermes bridge, role routing
├── core/           # 9-stage pipeline, gates, voting, recon, validation
├── db/             # Knowledge-store migrations (SQLite)
├── docs/           # Mintlify documentation site
├── engagement/     # Per-target engagement folder (CBH-derived)
├── eval/           # Skills-on vs skills-off ablation harness
├── interface/      # CLI / TUI / main entry point
├── playbooks/      # 7 hunt playbooks (CBH-derived, 12-section format)
├── report/         # Reporting, dedupe, SARIF 2.1.0
├── runtime/        # Pluggable sandbox backends (Docker / local / native)
├── skills/         # Markdown knowledge packs (vulnerabilities, frameworks, …)
├── telemetry/      # PostHog + Scarf stubs (no network calls)
├── tools/          # 24+ function tools exposed to agents
└── utils/          # Small helpers
```

A few root-level files are helper scripts used
during local development (`prometheus_comms.py`, `prometheus-safe-launch.sh`,
`prometheus_tail.sh`).
The canonical tool is the `prometheus` console script installed by the
Python package.

---

## Documentation

Full documentation lives in [`docs/`](docs/) and is published as a
Mintlify site. The README is a curated front door; for the details go
to the docs:

- [Quickstart](docs/quickstart.mdx)
- [LLM providers](docs/llm-providers/) (Anthropic, OpenAI, Vertex, Azure, Bedrock, local)
- [Integrations](docs/integrations/) (GitHub Actions, CI/CD)
- [Advanced configuration](docs/advanced/configuration.mdx)
- [Skills](docs/advanced/skills.mdx)
- [Sandbox backends](docs/tools/sandbox.mdx)
- [Benchmarks](docs/benchmarks.md) (XBOW validation-benchmarks harness)

---

## Status

Prometheus v1.0.0 is **Alpha**. The 7-Question Gate, Always-Rejected /
Conditionally-Valid matrices, N-run voting, and the seven hunt playbooks
are in place; broader vulnerability coverage, a stable CI workflow, and
additional sandbox backends are tracked in [CHANGELOG.md](CHANGELOG.md)
under `[Unreleased]`. Expect breaking changes.

Test count at v1.0.0: **262 tests passing** (see
`cf3de8e fix: 5-phase audit remediation — 262 tests pass`).

---

## Contributing

We welcome contributions of code, docs, and new skills — see
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow. By contributing you
agree to follow the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and to
license your contribution under the project's MIT license. New
contributors are added to [AUTHORS](AUTHORS) on their first merged PR.

Open a [pull request](https://github.com/StefanIsMe/Prometheus/pulls) or
[issue](https://github.com/StefanIsMe/Prometheus/issues).

---

## Legal

- **License:** [MIT](LICENSE) — Copyright (c) 2026 Stefan Carter.
- **Disclaimer:** [DISCLAIMER.md](DISCLAIMER.md) — the Author and
  contributors are **not liable** for any damages arising from your
  use of the software. **You assume all risk.** Use only against
  systems you own or have explicit written authorization to test.
- **Code of Conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- **Security policy:** see [SECURITY.md](SECURITY.md) — file a private
  GitHub Security Advisory at
  `https://github.com/StefanIsMe/Prometheus/security/advisories/new`.
  Only the latest release (v1.0.0) is supported; responses are
  best-effort.
- **Trademark:** "Prometheus" is the project name. The Prometheus
  trademark is not asserted on third-party forks or downstream
  distributions of this MIT-licensed code.

By using Prometheus or any of the code in this repository you agree
to the MIT license, the [DISCLAIMER.md](DISCLAIMER.md), and the
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Acknowledgments

Prometheus builds on the work of the following open-source projects
and their maintainers:

- **[LiteLLM](https://github.com/BerriAI/litellm)** — unified LLM
  provider routing
- **[Caido](https://github.com/caido/caido)** — HTTP proxy SDK
- **[Nuclei](https://github.com/projectdiscovery/nuclei)** — template
  format reference
- **[Playwright](https://github.com/microsoft/playwright)** — headless
  browser automation
- **[Textual](https://github.com/Textualize/textual)** — terminal UI
- **[VulnBot](https://arxiv.org/abs/2501.13411)** — inspiration for the
  Penetration Task Graph (PTG)
- **[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** —
  vendored inside the Claude-BugHunter skill bundle

See [AUTHORS](AUTHORS) for the full project lineage and per-project
attribution.

---

<p align="center">
  <sub>Prometheus v1.0.0 · MIT · © 2026 Stefan Carter</sub>
</p>
