# Prometheus Integration Plan — Stealing the Best of VVAH + Claude-BugHunter

**Date:** 2026-06-15
**Status:** Draft, awaiting review
**Audits this plan draws from:**
- `/home/stefan/audit-reports/vvah-audit.md`
- `/home/stefan/audit-reports/claude-bughunter-audit.md`
- `/home/stefan/audit-reports/prometheus-gap-analysis.md` (VVAH)
- `/home/stefan/audit-reports/prometheus-cbh-gap-analysis.md` (CBH)

**Goal:** Merge the strongest ideas from Visa's VVAH and ElementalSouls' Claude-BugHunter into Prometheus without breaking the existing PRD. Prioritize changes that directly attack the 0-finding problem and the open-questions in the PRD.

**Authoritative source-of-truth files inside Prometheus:**
- `PROMETHEUS_BUILD_SPEC_PRD.md` — v1 scope, v1 classes, validation rules.
- `prometheus/config/models.py` — **broken (file ends in `_OL...`, invalid syntax per PRD §3.5) — fix first.**

---

## TL;DR — The Two Systems, The Lesson

| System | What it is | What it's good at | What Prometheus should steal |
|---|---|---|---|
| **VVAH** | 9-stage static analysis pipeline for source code | Structured pipeline, N-run LLM voting, deterministic prefilter, SARIF emission, threat-model-before-analysis, redaction at dual boundary | The *shape* of the pipeline, the per-stage config, the N-run voting, SARIF, the threat-model step |
| **Claude-BugHunter** | Playbook bundle for live web app bug hunting | Domain knowledge (7-Question Gate, Always-Rejected/Conditionally-Valid matrix, per-class hunt playbooks, chain templates, scope guardrails, SPA-aware recon, eval framework) | The *content* — encoded as data tables and structured skill files, the deterministic engine, the engagement folder |
| **Prometheus (today)** | 1277-line monolithic scanner + 2536-line agent loop | Multi-agent graph, target registry, knowledge store, report writer | Has the runner. Needs the playbook + the pipeline shape |

**One-line synthesis:** VVAH gives Prometheus the pipeline structure. CBH gives it the playbook content. The result is a 9-stage threat-modeled, N-run-voted, deterministically-prefiltered, playbook-driven, scope-guarded, chain-aware bug-bounty pipeline.

---

## The Plan — 4 Phases, 14 Changes

Ordered for an iterative Claude-driven /loop session (matches the RL loop's SCAN/REVIEW/FIX/TEST actions). Each phase produces a runnable, measurable improvement.

### Phase 0 — Foundation (must do first; do not skip)

> Goal: Make the repo importable, get the model routing right, set up the engagement-folder filesystem. Nothing else matters until these work.

#### Change 0.1 — Repair `prometheus/config/models.py`

**What it is:** The current file ends in `_OL...` invalid syntax (PRD §3.5). Without this fix, `python3 -m compileall prometheus` fails and no scan can launch.

**Where it comes from:** PRD §3.5 + §5.1.

**What Prometheus needs:**
1. Replace `prometheus/config/models.py` with a clean re-export of `hermes_bridge.py`.
2. Add `prometheus/config/hermes_bridge.py` per PRD §5.1 — calls `hermes_cli.config.load_config()`, returns `HermesModelResolution(provider, model, base_url, api_key_env_name, api_key_present, source_profile)`.
3. Add `apply_hermes_model_defaults()` that wires the resolution into the OpenAI Agents SDK.
4. Stop treating Hermes use as optional. Default `use_hermes_model=True`. Tests can flip it to `False` via env var.

**Files to create/modify:**
- Create: `prometheus/config/hermes_bridge.py`
- Rewrite: `prometheus/config/models.py` (1-line re-export of `hermes_bridge.py`)
- Modify: `prometheus/config/settings.py:20-66` (drop the local LLM config; keep only Prometheus-specific runtime settings)
- Modify: `prometheus/config/loader.py:24-143` (stop persisting LLM config to `cli-config.json`)
- Modify: `prometheus/core/runner.py:138-205` (call `apply_hermes_model_defaults()` at startup)
- Modify: `prometheus/interface/main.py:79-83` (Hermes is canonical, not optional)

**Validation:**
- `python3 -m compileall $PROMETHEUS_SOURCE/prometheus` exits 0.
- `PYTHONPATH=... pytest tests/test_hermes_model_config.py` collects and passes.
- `prometheus --help` doesn't crash on missing config.

**RL-loop action:** `FIX`.

#### Change 0.2 — Engagement-folder filesystem

**What it is:** A per-target folder at `~/.prometheus/engagements/<domain>/` with `scope.md`, `findings/`, `evidence/`, `state.json`, `engine.log`. Mirrors CBH's `hunt acme-bb` scaffold.

**Where it comes from:** CBH `engine/state.py` + `engine/scope.py` + INSTALL.md (engagement-folder description).

**What Prometheus needs:**
1. New module: `prometheus/engagement/state.py` (port of CBH's `state.py`).
2. New module: `prometheus/engagement/manager.py` — `Engagement.create(domain) -> Engagement` scaffolds the folder; `Engagement.load(domain) -> Engagement` rehydrates.
3. Schema for `state.json`: `name`, `created`, `phase`, `targets`, `surface`, `tested`, `candidates`, `confirmed` (mirror CBH).
4. Atomic save: dump to `.tmp`, then `os.replace`.
5. Helper: `evidence_path(fname) -> Path` joins `evidence/`.

**Files to create:**
- `prometheus/engagement/__init__.py`
- `prometheus/engagement/state.py`
- `prometheus/engagement/manager.py`
- `prometheus/engagement/scope.py` (port from CBH — see Change 1.1)

**Validation:**
- `Engagement.create("acme-bb").save()` creates `~/.prometheus/engagements/acme-bb/` with the expected layout.
- `Engagement.load("acme-bb")` rehydrates state from `state.json`.
- Resume = instantiate another `Engagement` against the same dir. Counts match.

**RL-loop action:** `FIX`.

#### Change 0.3 — Scope guardrail

**What it is:** A 4-pattern allowlist (bare domain, `*.example.com`, exact, CIDR) + regex via `re:` + **deny-wins** + **default-deny** + **suffix-confusion guard**. Refuses to dispatch any command whose URL host fails `in_scope_host()`.

**Where it comes from:** CBH `engine/scope.py` (200 lines of stdlib).

**What Prometheus needs:**
1. Port `prometheus/engagement/scope.py` directly from CBH.
2. Wire the Tor-proxy check in `execution.py:_check_tor_proxy_required` to also call `in_scope_host()` — refuse to dispatch any OOS URL.
3. Add a scope-audit pass to the report: extract all hosts touched during the run, flag any not in scope with `⚠️ SCOPE WARNING`.
4. Test with a hostile case: a target that redirects to `evil.com` during PoC validation. The scope guardrail catches it before the request goes out.

**Files to create/modify:**
- Create: `prometheus/engagement/scope.py` (port)
- Modify: `prometheus/core/execution.py:_check_tor_proxy_required` (add `in_scope_host` check)
- Modify: `prometheus/tools/reporting/tool.py:create_vulnerability_report` (add scope-warning block)

**Validation:**
- `Scope(in_scope=["example.com"], out_of_scope=["evil.com"]).in_scope_host("api.example.com")` → True.
- `Scope(...).in_scope_host("notexample.com")` → False (suffix confusion).
- `Scope(...).in_scope_host("evil.com")` → False (deny wins).
- `Scope(...).in_scope_host("random.com")` → False (default deny).

**RL-loop action:** `FIX`.

### Phase 1 — Threat model + Deterministic prefilter (the 0-finding attack)

> Goal: Make scans focused (VVAH-style threat model) and findings predictable (CBH-style always-rejected matrix). These are the two highest-leverage changes per both gap analyses.

#### Change 1.1 — Threat model before analysis (s2-equivalent)

**What it is:** A target-scoped STRIDE/OWASP/MASVS/CWE model that narrows the *finding search space* before the agent runs. Returns a `ThreatModel` with target_kind, top-5 STRIDE categories, OWASP/MASVS/CWE categories to prioritize, 3-5 concrete hypotheses to test first.

**Where it comes from:** VVAH `s2 threatmodel` role + docs/architecture.md.

**What Prometheus needs:**
1. New module: `prometheus/core/threat_model.py`.
2. Inputs: `scan_config.targets`, `scan_config.tech_stack`, `scan_config.user_instructions`, output from Change 0.2's `Engagement`.
3. Output: `ThreatModel` dataclass + `state.json: threat_model` field.
4. Implementation: one LLM call (Sonnet-tier) with a curated prompt that selects STRIDE categories + OWASP Top 10 / MASVS / CWE memory-safety baselines.
5. Feed into `stage3_decompose` as a constraint (this is also part of Change 0.4 below).
6. Store in `engagement_dir/runs/<run_id>/stages/s2_threatmodel.json`.

**Files to create/modify:**
- Create: `prometheus/core/threat_model.py`
- Create: `prometheus/agents/prompts/threatmodel.md` (the prompt)
- Modify: `prometheus/core/runner.py:138-205` (call threat model after recon, before deep-dive)

**Validation:**
- For a known web-api target, threat model returns STRIDE categories ranked with `Spoofing`, `Tampering`, `Elevation of Privilege` in top 3.
- For a known native-binary target, threat model returns CWE memory-safety categories in top 3.
- Re-running the threat model on the same target returns the same structure (within LLM non-determinism, but stable enough).

**RL-loop action:** `FIX`.

#### Change 1.2 — Always-Rejected / Conditionally-Valid matrix as data

**What it is:** Two enumerative tables, encoded as JSON, that the validator consults. The Always-Rejected list has 20+ entries (missing CSP alone, internal hostname alone, etc.). The Conditionally-Valid list has 12 chain entries (open redirect + OAuth = ATO, etc.).

**Where it comes from:** CBH `triage-validation` skill — the "always-rejected list" and "conditionally-valid-with-chain table" tables.

**What Prometheus needs:**
1. New data files:
   - `prometheus/skills/data/always_rejected.json` — port from CBH verbatim.
   - `prometheus/skills/data/conditionally_valid.json` — port from CBH verbatim.
2. New module: `prometheus/core/always_rejected.py` with a `match_rejection(finding) -> str | None` helper that returns the matching rule name (e.g. `"missing_csp_alone"`) or `None`.
3. Wire into `validate_finding` — if `match_rejection` returns a rule, the candidate is rejected with `rejection_reason` set to the rule name.
4. Wire into `create_vulnerability_report` — if a candidate's chain context matches a Conditionally-Valid entry but the chain isn't built, the report is blocked.

**Files to create:**
- `prometheus/skills/data/always_rejected.json`
- `prometheus/skills/data/conditionally_valid.json`
- `prometheus/core/always_rejected.py`
- `prometheus/core/conditionally_valid.py`

**Validation:**
- A finding with title "Missing CSP header on /api/v1/users" → `match_rejection` returns `"missing_csp_alone"`.
- A finding with title "Open redirect on /oauth/redirect" → returns `None` (not always-rejected; the Conditionally-Valid table says it needs an OAuth chain).
- The same finding + chain context "OAuth redirect_uri used" → `conditionally_valid` returns `True` with chain name `"open_redirect_oauth_ato"`.

**RL-loop action:** `FIX`.

#### Change 1.3 — 7-Question Gate with branched outcomes

**What it is:** Mirror CBH's `triage-validation` 7 questions in code, returning PASS / KILL_Q{n} / DOWNGRADE_Q{n} / CHAIN_REQUIRED.

**Where it comes from:** CBH `triage-validation` skill — the 7 questions + the 5-min/30-min time rules + the 4 outcomes.

**What Prometheus needs:**
1. New module: `prometheus/core/seven_question_gate.py`.
2. Mirror CBH's Q1–Q7 verbatim with branched outcomes.
3. Q1 = "5-step template filled in 5 min" — check that the candidate has request, response, impact, cost, setup sections.
4. Q6 = "actual victim data" — check that evidence contains a PoC response showing exfil/modification, not just a 200 OK.
5. Q7 = Always-Rejected (delegates to Change 1.2).
6. Time-boxed: `gate_with_timeout(finding, question_id, timeout_s=1800)` — kills the finding if Q6 takes >30 min.
7. Record the gate decision in `validation_runs` table (already in PRD §5.2).
8. Expose as CLI: `prometheus gate <finding.md>` returns 0=PASS, 1=DOWNGRADE, 2=KILL.

**Files to create:**
- `prometheus/core/seven_question_gate.py`
- `prometheus/agents/prompts/gate_questions.md` (the prompt)
- `prometheus/interface/cli.py` (add `gate` subcommand)

**Validation:**
- A finding with all 7 question answers met → PASS, exit 0.
- A finding with Q6 unanswered → KILL_Q6, exit 2.
- A finding in `validating` for >30 min → automatic KILL_Q6, exit 2.

**RL-loop action:** `FIX`.

### Phase 2 — Pipeline shape (VVAH-style staging)

> Goal: Refactor the monolithic `runner.py` into 9 explicit stages, each with its own config, checkpoint, and per-stage LLM routing. Unlocks the RL loop's ability to act on a specific stage.

#### Change 2.1 — Stage 4: SPA-aware recon (mechanical, deterministic)

**What it is:** A deterministic pre-step that fetches the seed HTML, downloads same-origin JS bundles, regex-mines API routes, scans for secrets, classifies endpoints. The deep-dive agent then has the real surface, not the LLM-guessed surface.

**Where it comes from:** CBH `engine/recon.py` (stdlib-only) + the `auth_enforcement_sweep` for OpenAPI.

**What Prometheus needs:**
1. New module: `prometheus/core/recon.py` (port from CBH).
2. Run as a deterministic pre-step in `stage4_deepdive` (or new `stage3_recon`).
3. Output: `engagement_dir/runs/<run_id>/recon/arsenal.md` with endpoints, params, secrets, classification per URL.
4. The agent's deep-dive then loads `arsenal.md` as context.
5. Also port `auth_enforcement_sweep` as `prometheus/core/openapi_sweep.py` for OpenAPI-aware auth-bypass detection.

**Files to create:**
- `prometheus/core/recon.py`
- `prometheus/core/openapi_sweep.py`

**Validation:**
- A seed URL with React/Next.js returns the JS-bundle endpoints in `arsenal.md`.
- A target with `openapi.json` and 5 declared-secured ops returns 5 auth-probe entries in `openapi/auth_gaps.json`.
- A target with 3 secrets in JS bundles returns 3 entries in `info-leak` findings.

**RL-loop action:** `FIX`.

#### Change 2.2 — Stage 4: N-run LLM voting

**What it is:** Run the deep-dive 3 times per chunk with `temperature > 0`. Keep findings that pass a vote threshold (2 of 3 default). This is the VVAH `s4 deepdive` + `s5 prefilter` pattern.

**Where it comes from:** VVAH `s4 deepdive` role + docs/features.md (the "max precision" profile uses `step4.runs: 4, vote_threshold: 3`).

**What Prometheus needs:**
1. Add a config block to `prometheus/config/runner.yaml` (or wherever): `deepdive: { runs: 3, vote_threshold: 2, parallel: true }`.
2. In `prometheus/core/runner.py:stage4_deepdive`, run the agent loop N times.
3. Collect findings, group by `(vuln_type, endpoint, parameter, auth_state)`.
4. Drop findings with `votes < vote_threshold`.
5. Keep `validation_judge.py` as a *post-vote* heuristic (per PRD).
6. Cost: 3× deep-dive tokens. Mitigated by per-stage `max_budget_usd` cap.

**Files to modify:**
- `prometheus/core/runner.py:stage4_deepdive` (add N-run + vote)
- `prometheus/config/` (add deepdive config block)

**Validation:**
- A scan that previously produced 0 findings with `runs: 1` now produces ≥1 with `runs: 3, vote_threshold: 2`.
- The same finding appearing across multiple runs gets `votes: 3` and is kept.
- A hallucinated finding from one run gets `votes: 1` and is dropped.

**RL-loop action:** `FIX`.

#### Change 2.3 — Stage 6: Adversarial verification (separate stage)

**What it is:** Promote `verify_finding` from a tool (called mid-conversation) to a separate `stage6_verify` with its own model role. Returns `TRUE_POSITIVE` / `FALSE_POSITIVE` + CVSS 3.1. Uses a *different* model than the deep-dive.

**Where it comes from:** VVAH `s6 verify` role (per-role model routing, agentic verifier with Read/Glob/Grep).

**What Prometheus needs:**
1. New module: `prometheus/core/stage6_verify.py`.
2. New role: `verify` in `prometheus/config/role_routing.yaml` (see Change 4.1).
3. Output: `engagement_dir/runs/<run_id>/stages/s6_verify.json` with per-candidate verdict + CVSS + evidence pointers.
4. Drop findings that fail verification: set `lifecycle_status = "rejected"`, `rejection_reason = "s6_verify_false_positive"`.

**Files to create/modify:**
- Create: `prometheus/core/stage6_verify.py`
- Create: `prometheus/agents/prompts/verify.md`
- Modify: `prometheus/core/runner.py` (wire stage6 as a separate pipeline step)

**Validation:**
- A candidate from stage4 deep-dive gets a `TRUE_POSITIVE` verdict when re-tested.
- A candidate that was a hallucination gets `FALSE_POSITIVE` and is rejected.
- Stage6 uses a different model tier than stage4 (e.g., Sonnet for stage4, Opus for stage6).

**RL-loop action:** `FIX`.

#### Change 2.4 — Stage 7: Dedup with semantic + line tolerance

**What it is:** VVAH's `s7 dedup` runs deterministic + semantic dedup. Prometheus already has `prometheus/report/dedupe.py` — extend it with semantic dedup (embedding similarity).

**Where it comes from:** VVAH `s7 dedup` (deterministic + semantic toggle, `line_tolerance`, `pre_verify_threshold`).

**What Prometheus needs:**
1. Extend `prometheus/report/dedupe.py` with an embedding-based semantic dedup.
2. Use the same Hermes-resolved embedding model.
3. Threshold: 0.85 cosine similarity for "same finding."

**Files to modify:**
- `prometheus/report/dedupe.py` (add semantic dedup)

**Validation:**
- Two findings that differ only in wording get dedup'd.
- Two findings that differ in vuln_class or endpoint don't get dedup'd.

**RL-loop action:** `FIX` (small).

### Phase 3 — Playbook content (CBH-style)

> Goal: Convert the 7 v1-class prompt fragments into 12-section playbooks following CBH's structure. Encode chain templates. Wire evidence-hygiene as a first-class skill.

#### Change 3.1 — Per-vuln-class playbooks (12 sections each)

**What it is:** For each v1 class (IDOR, auth bypass, account enumeration, SSRF, CORS, exposed unauthenticated, source map), write a 12-section `hunt-<class>.md` following CBH's structure: Crown Jewel Targets, OOB gate, Attack Surface Signals, methodology, payloads, root causes, bypasses, Gate 0, real impact, chains, related skills.

**Where it comes from:** CBH `hunt-xss`, `hunt-sqli`, `hunt-ssrf`, `hunt-idor`, `hunt-cors` — adapt their structure to v1 classes.

**What Prometheus needs:**
1. For each of the 7 v1 classes, create `prometheus/playbooks/hunt-<class>.md` with all 12 sections.
2. Move them from `prometheus/skills/vulnerabilities/` (agent prompt fragments) to `prometheus/playbooks/<class>.md` (structured workflow).
3. Have the agent's deep-dive load the playbook for the class it's currently hunting, not a generic "skills" list.
4. Track playbook adherence: did the agent do step 1-2-3?

**Files to create:**
- `prometheus/playbooks/hunt-idor.md`
- `prometheus/playbooks/hunt-auth-bypass.md`
- `prometheus/playbooks/hunt-account-enumeration.md`
- `prometheus/playbooks/hunt-ssrf.md`
- `prometheus/playbooks/hunt-cors.md`
- `prometheus/playbooks/hunt-exposed-unauthenticated.md`
- `prometheus/playbooks/hunt-source-map.md`

**Validation:**
- Each playbook has all 12 sections.
- A finding classified as `auth_bypass` from the deep-dive matches a methodology step in `hunt-auth-bypass.md`.

**RL-loop action:** `FIX` (this is multi-day; consider as one PR with 7 files).

#### Change 3.2 — Chain templates

**What it is:** A data file with 12+ known chain patterns (open redirect + OAuth = ATO, etc.) + a `find_chain_links(finding) -> list[Chain]` helper.

**Where it comes from:** CBH `triage-validation` Conditionally-Valid table + `hunt-xss` chains section.

**What Prometheus needs:**
1. Create `prometheus/chains/known_chains.json` (port from CBH's table).
2. New module: `prometheus/core/chain_linker.py` with `find_chain_links(finding) -> list[Chain]`.
3. When 2+ findings share `(domain, asset_class)` and match a known chain pattern, propose a chain and present it for human review.
4. Wire into `create_vulnerability_report` — chains are presented as separate reportable items, with severity escalated per the chain rule.

**Files to create:**
- `prometheus/chains/known_chains.json`
- `prometheus/core/chain_linker.py`

**Validation:**
- Two findings (open redirect + OAuth redirect_uri use) on the same domain get linked into chain `"open_redirect_oauth_ato"`.
- The chain's severity is escalated from P3 (open redirect alone) to P1 (ATO via OAuth).

**RL-loop action:** `FIX` (defer to v2 if v1 is the priority; the data is the priority, not the linker).

#### Change 3.3 — Evidence-hygiene skill

**What it is:** Port CBH's `evidence-hygiene` skill content as `prometheus/skills/evidence-hygiene.md`. Wire as a slash command `/evidence`. Add a screenshot post-check that scans for cookie-name substrings.

**Where it comes from:** CBH `evidence-hygiene` skill — the 5-step screenshot capture order, ranked redaction methods, post-submission credential rotation.

**What Prometheus needs:**
1. Create `prometheus/skills/evidence-hygiene.md` (port from CBH).
2. Add `/evidence` slash command that prints the skill content.
3. Add `prometheus/tools/evidence_post_check.py` that scans images for cookie-name substrings and warns.

**Files to create:**
- `prometheus/skills/evidence-hygiene.md`
- `prometheus/tools/evidence_post_check.py`

**Validation:**
- The skill content is read by the agent and surfaced when `/evidence` is invoked.
- A screenshot with `session=abc123` in the URL triggers a warning.

**RL-loop action:** `FIX` (small).

### Phase 4 — VVAH-style staging + reproducibility

> Goal: Get the 9-stage pipeline shape right, with per-stage config and per-stage model routing. Reproducibility via `run_manifest.json` with config hash + prompt hash + model IDs. The "MTTA" metric from VVAH.

#### Change 4.1 — Per-role model routing

**What it is:** A config-driven `{id, via}` per pipeline stage, so an Opus-tier model isn't doing the same work as a Haiku-tier model. Mirrors VVAH `models:` block.

**Where it comes from:** VVAH `docs/models.md` + `docs/features.md` (the `full.yaml` profile mixes `cli`/`sdk`/`openai` per role).

**What Prometheus needs:**
1. New file: `prometheus/config/role_routing.yaml` mapping each stage role to a model tier.
2. Make `runner.py` resolve the model per stage, not per scan.
3. Update `configure_sdk_model_defaults` to accept a `stage` argument.
4. Hermes bridge from Change 0.1 provides the model catalog.

**Files to create/modify:**
- Create: `prometheus/config/role_routing.yaml`
- Modify: `prometheus/core/runner.py` (per-stage model resolution)
- Modify: `prometheus/config/models.py` / `hermes_bridge.py` (per-stage lookup)

**Validation:**
- `stage2_threatmodel` uses Haiku (cheap reconnaissance).
- `stage4_deepdive` uses Sonnet (main hunt).
- `stage6_verify` uses Opus (adversarial verification).
- The `run_manifest.json` records which model ran each stage.

**RL-loop action:** `FIX`.

#### Change 4.2 — `run_manifest.json` with config + prompt hashing

**What it is:** Extend `ScanPersistence` to record config hash, prompt hash, model IDs per stage, per-stage duration.

**Where it comes from:** VVAH `run_manifest.json` (tool version, model roles, config hash, target git SHA, timing).

**What Prometheus needs:**
1. Modify `prometheus/core/scan_persistence.py:record_scan_start` to hash the scan config + prompt templates + model IDs.
2. Add per-stage checkpoint records (file path, hash, duration).
3. Store in `run_manifest.json` per VVAH's schema.

**Files to modify:**
- `prometheus/core/scan_persistence.py:record_scan_start` (add hashing)
- `prometheus/core/runner.py` (write per-stage records)

**Validation:**
- Two runs with the same config produce the same `run_manifest.json` config hash.
- Two runs with different prompts produce different prompt hashes.
- The `run_manifest.json` is human-readable (JSON, not pickle).

**RL-loop action:** `FIX` (small).

#### Change 4.3 — SARIF 2.1.0 emission (defer to v2 unless needed for RL)

**What it is:** Emit SARIF 2.1.0 from the `finding_candidates` table. `tool.driver.name = "Prometheus"`. Include `cwe`, `cvss`, `evidence` paths in `properties`.

**Where it comes from:** VVAH `s9 SARIF` + `report/enrich.py: md_to_sarif()`.

**What Prometheus needs:**
1. New module: `prometheus/report/sarif.py` emitting SARIF 2.1.0.
2. Use the same tool/driver naming convention.
3. Include `cwe`, `cvss`, `evidence` paths.

**Files to create:**
- `prometheus/report/sarif.py`

**Validation:**
- The emitted SARIF validates against the SARIF 2.1.0 schema.
- Round-trip: SARIF → findings list matches the original `finding_candidates`.

**RL-loop action:** `FIX` (defer; not blocking v1).

#### Change 4.4 — Eval framework (long-term, separate repo)

**What it is:** A headless `claude -p` agent pointed at self-grading vulnerable targets. Skills-on vs skills-off ablation. Per-class solve rates.

**Where it comes from:** CBH `eval/` (Juice Shop + PortSwigger Academy).

**What Prometheus needs:**
1. A separate `prometheus-eval/` repo or `prometheus/eval/` subfolder.
2. Juice Shop (Docker) + PortSwigger Academy as targets.
3. `run_eval.py` with `--baseline` (no new modules) and `--conditions skills` (with new modules).
4. Per-run records: solved, turns, cost, tokens, per-class solve rates.

**Files to create (separate repo recommended):**
- `prometheus-eval/run_eval.py`
- `prometheus-eval/oracle_juice_shop.py`
- `prometheus-eval/oracle_portswigger.py`
- `prometheus-eval/challenges.json`
- `prometheus-eval/ps_labs.json`

**Validation:**
- Ablation: skills-on vs skills-off shows a positive delta on at least one vuln class.
- Per-class solve rates: IDOR ≥ 50%, auth bypass ≥ 30%, etc.

**RL-loop action:** `TEST` (this is the natural home of the RL loop's TEST action).

---

## How the Changes Map to the RL Loop

The `/loop 5m /prom-rl` workflow is a SCAN/REVIEW/FIX/TEST cycle. Here's how each change lands:

| Change | Primary RL action | Secondary RL action | Time budget |
|---|---|---|---|
| 0.1 Repair config/models.py | FIX | — | 1 day |
| 0.2 Engagement-folder filesystem | FIX | — | 1 day |
| 0.3 Scope guardrail | FIX | TEST (unit tests) | 0.5 day |
| 1.1 Threat model | FIX | SCAN (validate on OpenSea) | 1 day |
| 1.2 Always-Rejected matrix | FIX | — | 0.5 day |
| 1.3 7-Question Gate | FIX | REVIEW (replace validation_judge) | 1 day |
| 2.1 SPA-aware recon | FIX | SCAN (validate on OpenSea) | 1-2 days |
| 2.2 N-run LLM voting | FIX | SCAN (compare runs=1 vs runs=3) | 1 day |
| 2.3 Stage 6 verify (separate) | FIX | — | 0.5 day |
| 2.4 Semantic dedup | FIX | TEST (unit tests) | 0.5 day |
| 3.1 Per-vuln-class playbooks | FIX (multi-file PR) | — | 3-5 days |
| 3.2 Chain templates | FIX (data file first) | — | 1 day data, 2 days linker |
| 3.3 Evidence-hygiene | FIX | — | 0.5 day |
| 4.1 Per-role model routing | FIX | SCAN (cost comparison) | 1-2 days |
| 4.2 run_manifest.json | FIX | — | 0.5 day |
| 4.3 SARIF 2.1.0 | FIX (defer to v2) | — | 1 day |
| 4.4 Eval framework | TEST | — | 3-5 days |

**Total v1 effort:** ~17-25 days of focused work. Most can be done as small FIX actions interleaved with SCAN actions to validate.

---

## Suggested Iteration Sequence (10-15 /loop turns)

If the user drives the loop manually, the next 10-15 actions could be:

1. **FIX** — Repair `prometheus/config/models.py` (Change 0.1). After: `python3 -m compileall` exits 0.
2. **FIX** — Add `prometheus/engagement/` package + `state.py` + `manager.py` (Change 0.2). After: `Engagement.create("acme-bb")` scaffolds the folder.
3. **FIX** — Port `prometheus/engagement/scope.py` (Change 0.3). After: scope guardrail refuses `notexample.com`.
4. **FIX** — Add `prometheus/skills/data/always_rejected.json` (Change 1.2). After: `match_rejection("Missing CSP")` returns `"missing_csp_alone"`.
5. **FIX** — Add `prometheus/core/seven_question_gate.py` (Change 1.3). After: `prometheus gate` CLI works.
6. **FIX** — Port `prometheus/core/recon.py` (Change 2.1). After: OpenSea seed URL returns the SPA's JS-bundle endpoints.
7. **FIX** — Add `prometheus/core/threat_model.py` (Change 1.1). After: OpenSea threat model returns `web-api` + `OWASP Top 10` + 3 STRIDE categories.
8. **SCAN** — Re-run OpenSea with all the above. Expected outcome: 0 → 1+ findings per the new gate + recon + threat model.
9. **REVIEW** — The REVIEW action should now report gate decisions (KILL_Q6, CHAIN_REQUIRED, etc.) instead of just "0 findings."
10. **FIX** — Add N-run voting (Change 2.2). Set `runs: 3, vote_threshold: 2`. Cost: 3× tokens.
11. **FIX** — Add per-role model routing (Change 4.1). Use Haiku for threat model, Sonnet for deep-dive, Opus for verify.
12. **SCAN** — Compare findings-per-token between (Haiku/Sonnet/Opus) and (Sonnet-everywhere). Pick the winner.
13. **FIX** — Add `run_manifest.json` with config hash (Change 4.2). After: 2 runs with different prompts have different manifest hashes.
14. **FIX** — Add evidence-hygiene skill (Change 3.3). After: `/evidence` slash command prints the skill content.
15. **TEST** — Add 3-5 unit tests for the gate, scope, and always-rejected modules.

After 15, the loop should be in a state where the 0-finding problem is either solved or attributable to a specific cause. If still 0, the cause is *target selection* (OpenSea rejects Tor, requires auth, etc.), not the pipeline.

---

## What to NOT do (and why)

These are tempting but harmful:

1. **Don't write SARIF before you have any findings.** SARIF is a *format*; without findings to emit, the SARIF emitter is unvalidated code. Defer to v2.
2. **Don't add chain construction before you have multi-class findings.** Chains are a 2nd-order feature; need 1st-order findings first.
3. **Don't port the eval framework before the playbooks are written.** The eval measures skill contribution; if the skills aren't there, the eval measures nothing.
4. **Don't refactor `runner.py` into 9 stages in one go.** Refactor incrementally, one stage at a time, each measured by a SCAN/REVIEW cycle. The RL loop can't act on a 9-stage refactor; it can act on "stage 2.1 recon works, 2.2 voting works, ..."
5. **Don't break the live RL loop.** The watchdog (PID 1604) and the loop's `state.json` roundtrip must keep working. Test in a branch, merge only after REVIEW passes.
6. **Don't add new dependencies without auditing them.** Prometheus already has a heavy dep tree (VVAH is stdlib-only, CBH is stdlib-only — both are minimal on purpose).
7. **Don't auto-submit to HackerOne/Bugcrowd.** CBH explicitly does not. VVAH explicitly does not. PRD §2.3 says no. The human reviews.

---

## Open Questions for the User

These need user input before continuing:

1. **Target priority.** OpenSea is the best target for automated loops (per the RL memory). But the 0-finding problem may be a target problem, not a pipeline problem. Should we add a fallback target (Bullish, inDrive) for when OpenSea is stuck?
2. **Cost cap.** N-run voting + per-role routing increases tokens. The user is on a paid model. What's the per-scan cost ceiling?
3. **Scope of v1.** The PRD's v1 classes are IDOR, auth bypass, account enumeration, SSRF, CORS, exposed unauthenticated, source map. Should we add the CBH classes (race conditions, OAuth, GraphQL, etc.) in v1 or defer to v2?
4. **Eval target.** CBH uses Juice Shop + PortSwigger Academy. Should Prometheus adopt the same, or use a different target (e.g., a synthetic target spun up for the test)?
5. **The 3 persistence layers (PRD §3.3).** Should the engagement-folder filesystem replace or supplement the existing `KnowledgeStore` + `ScanPersistence` + `TargetRegistry`? My recommendation: supplement, then migrate. The user should approve.

---

## Cross-References

- PRD: `/home/stefan/prometheus-source/PROMETHEUS_BUILD_SPEC_PRD.md`
- VVAH audit: `/home/stefan/audit-reports/vvah-audit.md`
- CBH audit: `/home/stefan/audit-reports/claude-bughunter-audit.md`
- VVAH gap analysis: `/home/stefan/audit-reports/prometheus-gap-analysis.md`
- CBH gap analysis: `/home/stefan/audit-reports/prometheus-cbh-gap-analysis.md`
- Plan file (originating from /loop session): `/home/stefan/.claude/plans/imperative-sleeping-bunny.md`
