# Security Policy

Prometheus is an open-source, Alpha-stage security-testing tool. We take
vulnerabilities in the tool itself seriously, and we ask that you report
them through the channels below rather than opening a public issue.

For the legal framework (authorised use, no warranty, limitation of
liability), see [`DISCLAIMER.md`](DISCLAIMER.md). For community
standards, see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## Supported versions

| Version  | Supported                                            |
|----------|------------------------------------------------------|
| `v1.0.0` | ✅ Receives security fixes (latest release)          |
| `< v1.0.0` | ❌ End-of-life — no patches will be issued          |

Prometheus is currently in **Alpha** and ships breaking changes. We do
not maintain security branches for older releases. Please run the
[latest tagged release](https://github.com/StefanIsMe/Prometheus/releases)
whenever possible.

---

## How to report a vulnerability

Use **one** of the channels below. Do **not** open a public issue for
high- or critical-severity findings.

### 1. GitHub Security Advisories (preferred — private)

File a private advisory:

> https://github.com/StefanIsMe/Prometheus/security/advisories/new

This routes the report through GitHub's private advisory workflow. Only
the maintainers of `StefanIsMe/Prometheus` will see it, and you can
choose whether to disclose publicly when a fix is published.

### 2. Public issue (low-severity findings only)

For low-severity issues with no live exploit path, you may open a public
issue with the `security` label:

> https://github.com/StefanIsMe/Prometheus/issues/new

**Do not** post live exploit payloads, stolen credentials, unredacted
target details, or step-by-step reproduction against a third-party
system in a public issue. Use the private channel above for those.

---

## What to include in your report

The more complete the report, the faster we can triage. A good report
covers:

- **Affected version(s)** — output of `prometheus --version` (or the
  commit SHA) and the commit/tag you reproduced against
- **Vulnerability class** — e.g. RCE in the sandbox, path traversal,
  prompt injection, secret disclosure, supply-chain compromise
- **Environment** — OS, Python version, Docker version, sandbox
  backend, LLM provider, install method (`uv` / `pipx` / `install.sh`)
- **Reproduction steps** — minimal, deterministic steps we can run on
  a fresh clone; include the exact `--target`, `--instruction`, or
  skill that triggers the bug
- **Impact** — what an attacker can do, who is affected, and the
  realistic severity (CVSS v3.1 vector if you can compute one)
- **Suggested fix** — optional, but appreciated
- **Disclosure preference** — anonymous, name-and-handle, or full
  attribution in the published advisory

Encryption is not required — the GitHub private-advisory flow is
end-to-end scoped to maintainers. If you have a payload that you would
rather not upload to GitHub, mention it in the report and we will work
out a side channel.

---

## Response timeline (best-effort)

Prometheus is maintained on a best-effort basis by a single
maintainer. The following targets are **aspirational**, not a service
level agreement:

| Stage                      | Target                                        |
|----------------------------|-----------------------------------------------|
| Acknowledgement            | Within ~1 week of receipt                     |
| Triage decision            | Within ~1 week of acknowledgement             |
| Patch for accepted issues  | As soon as practicable; ≤ 90 days for high/critical |
| Coordinated disclosure     | Jointly agreed with the reporter              |
| Public advisory            | Published at or before fix release, by default |

If a report is declined (out of scope, not reproducible, or by design),
we will explain why in the advisory thread. We may also close duplicate
advisories with a cross-reference.

---

## In-scope vs. out-of-scope

This policy covers **vulnerabilities in Prometheus itself** — the
binary, the package, the docs, the skill bundle, the proxy, the
sandbox, the report writer, and so on. It does **not** cover
vulnerabilities Prometheus *finds* in someone else's application;
those go through the affected application's own bug-bounty or
disclosure process, not this repository.

### In scope

- **Sandbox escape** — code that breaks out of the Docker / local /
  native sandbox (`prometheus/runtime/`)
- **Remote code execution in the host** — anything reachable from a
  crafted `--target`, `--instruction`, `--instruction-file`, scope
  file, skill, jinja prompt, or engagement folder
- **Path traversal / arbitrary file read or write** in
  `prometheus/engagement/`, `prometheus/report/`, or
  `prometheus_runs/`
- **Prompt injection** that causes Prometheus to execute an
  attacker-controlled action against a third party during an
  authorised scan
- **Secret leakage** — keys, tokens, or credentials written to logs,
  reports, or `prometheus_runs/` outputs in cleartext
- **Supply-chain risks** — typosquatted or malicious dependencies,
  skills, or jinja templates that ship in the bundle
- **Authentication / authorisation bugs** in the engagement folder,
  Hermes bridge, Nous OAuth flow, or CI workflows
- **Prototype pollution / deserialization flaws** in skill or
  report parsing

### Out of scope

- **Findings Prometheus produces about a target application** — these
  are reported to the target, not here. A finding in *your own* app
  discovered by running Prometheus against it is, by definition, not a
  vulnerability in Prometheus.
- **Unauthorised use of Prometheus against third-party systems** —
  this is a legal matter, not a security-reporting matter; see
  [`DISCLAIMER.md`](DISCLAIMER.md). If you observe Prometheus being
  used in a way that targets a system you own, contact law
  enforcement in your jurisdiction.
- **Model hallucinations in findings** — Prometheus is honest about
  being non-deterministic. A wrong IDOR report is a bug-bounty
  product-quality issue, not a security vulnerability in the tool
  itself. Open a public issue with a reproduction.
- **Vulnerabilities in upstream dependencies** — please report
  those upstream (LiteLLM, Caido, Playwright, Textual, …). We will
  bump the dependency on a best-effort basis once a fix is published.
- **Feature requests, UX issues, performance issues** — use the
  standard issue tracker.

### Things we will look at but typically will not pay bounties for

Prometheus is open-source and is **not** running a paid bug-bounty
program. We accept reports in good faith and credit reporters in the
advisory, but we do not currently offer monetary rewards.

---

## Safe harbor

Prometheus will not pursue civil or criminal legal action against, file
a complaint with law enforcement about, or restrict a researcher's
GitHub account on the basis of, security research directed at
**Prometheus itself** that is conducted in good faith and that:

- complies with this security policy and with
  [`DISCLAIMER.md`](DISCLAIMER.md);
- avoids privacy violations (no access to, modification of, exfiltration
  of, or destruction of data belonging to anyone other than the
  researcher);
- avoids service disruption (no denial-of-service against Prometheus
  infrastructure or third-party systems, no sustained load against
  the proxy);
- stops testing as soon as a vulnerability is confirmed and reports it
  through the channels above;
- does not exploit a vulnerability beyond what is necessary to
  demonstrate it; and
- does not publicly disclose the vulnerability before a coordinated
  disclosure date has been agreed.

This safe harbor extends only to research directed at Prometheus
itself. It does **not** authorise the use of Prometheus against
third-party systems — see [`DISCLAIMER.md`](DISCLAIMER.md).

We will not pre-commit to safe harbor for research that, in our
reasonable judgement, would have caused harm to third parties even if
the researcher's intent was good. If you are unsure whether a planned
test is in scope, ask first by opening a private advisory titled
"Pre-engagement question."

---

## Security Hall of Fame

We thank the following researchers for reporting vulnerabilities in
Prometheus (in chronological order):

> _No reports yet._

Reporters are added on publication of the corresponding advisory, with
the name and link of their choosing, unless they prefer to remain
anonymous.

---

## Acknowledgements

This policy is adapted from the
[GitHub Security Lab's recommended SECURITY.md template](https://github.com/github/.github/blob/main/SECURITY.md)
and the
[Disclose.io core terms](https://disclose.io/) (CC-BY-4.0). The
in-scope / out-of-scope framing borrows from the
[Strix project](https://github.com/usestrix/strix) (Apache-2.0) and
[Visa VVAH](https://github.com/visa/visa-vulnerability-agentic-harness)
(Apache-2.0) policies; see [`AUTHORS`](AUTHORS).
