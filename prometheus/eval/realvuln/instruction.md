"""Instruction file passed to prometheus via ``--instruction-file``.

We tell the agent this is a code-review scan of a static Python
project — no live deployment, no network, no Tor. The agent must
populate ``code_locations`` for every finding (those are the only
fields the RealVuln scorer matches on).
"""

# Why this lives in a .md file (not a .py string): the prometheus
# CLI's --instruction-file reads it verbatim, and a future iteration
# can edit it without redeploying the harness.
INSTRUCTION_TEMPLATE = """\
# Code-review scan — RealVuln-Benchmark target

You are reviewing a static Python application at: {repo_path}

This is a **whitebox / source-only** scan:

- The application is NOT running. Do not attempt to send HTTP requests.
- Do not use Tor, do not run network recon, do not invoke the target over the network.
- Read the source files directly (use your file-read tools).
- Do not execute the application, do not install its dependencies, do not run its tests.

## What to find

The ground truth includes the following vulnerability classes. For each
distinct root cause you find, call `create_vulnerability_report` ONCE
with the appropriate CWE:

- **Injection**: SQLi (CWE-89), NoSQLi (CWE-943), command injection (CWE-78), LDAPi (CWE-90), SSTI (CWE-1336 / CWE-94), XPathi (CWE-643), eval/exec (CWE-95)
- **Cross-site scripting**: reflected/stored/DOM XSS (CWE-79)
- **Cross-site request forgery** (CWE-352)
- **Server-side request forgery** (CWE-918)
- **XML external entity** (CWE-611)
- **Path traversal / LFI / RFI** (CWE-22)
- **Insecure deserialization** (CWE-502) — pickle, yaml.load, marshal
- **Broken authentication**: missing auth on sensitive endpoints (CWE-306), weak session (CWE-384), hardcoded credentials (CWE-798)
- **Broken access control / IDOR / missing authz** (CWE-862, CWE-639, CWE-285)
- **Cryptographic failures**: weak hash (CWE-327), hardcoded keys (CWE-321), insecure randomness (CWE-330), missing TLS verification (CWE-295)
- **Security misconfig**: debug enabled (CWE-489), default credentials (CWE-1392), permissive CORS (CWE-942), directory listing (CWE-548)
- **Insecure file upload** (CWE-434)
- **Open redirect** (CWE-601)
- **Mass assignment** (CWE-915)
- **Race condition / TOCTOU** (CWE-367)
- **Information disclosure**: stack traces (CWE-209), verbose errors (CWE-200 — only when concrete)
- **Supply chain**: known-vulnerable dependency (CWE-1395), missing SRI (CWE-353)
- **Business-logic flaws**: payment bypass, quota bypass, privilege escalation (CWE-840)

## CWE rules (strict)

- Use the **most specific** CWE you can. AVOID these broad parents — the
  benchmark scorer REJECTS them: CWE-74, CWE-20, CWE-200 (use CWE-209
  for concrete info disclosure), CWE-284, CWE-693.
- The CWE field must be a single string in the exact form `CWE-NNN`
  (e.g. `CWE-89`, not `CWE-89: SQL Injection`).

## Code locations (required)

The benchmark matches on `file` + `start_line` + `CWE`. For every
finding, populate `code_locations` with at least one entry:

- `file`: relative path from the repo root, no leading slash, no `..` (e.g. `app/views.py`)
- `start_line`: 1-indexed line of the vulnerable expression
- `end_line`: 1-indexed last line of the vulnerable block
- `snippet`: a few lines of surrounding code (optional but helps)

If you can't pinpoint a line, do not report the finding — better to
skip than to send a bogus location.

## Severity

Use one of: `critical`, `high`, `medium`, `low`, `info`. Match the
severity to actual exploitability, not to "this looks bad".

## Output discipline

- One finding per distinct root cause. Don't fragment a single SQLi
  across multiple lines into 5 reports.
- Don't report the same finding twice.
- Don't report theoretical issues that require impossible conditions.
- Don't report dependency CVEs you can't cite.

Begin: enumerate the Python files in the repo, then for each file
read it end-to-end and look for the patterns above. Be thorough — the
ground truth expects you to find real bugs, not just the obvious ones.
"""
