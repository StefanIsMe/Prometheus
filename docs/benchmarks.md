# Benchmarks

This document replaces the previous `benchmarks/README.md`, which was
removed on 2026-06-15. The old file made an unverified claim that
Prometheus `v0.4.0` achieved a **96%** success rate on the XBOW
benchmark, with no source code, no eval scripts, and no reproducible
run data. The file was originally added on 2026-01-23 by an outside
contributor on top of the old "Strix" tree, and was last edited to
link to a `StefanIsMe/prometheus-benchmarks` repository that does not
exist (404 on the GitHub API). The marketing-style claim has been
deleted; this stub is the only thing in its place until we have a
real, runnable benchmark to point at.

## Current status: 0/0

The XBOW validation-benchmarks corpus has not yet been executed
against the current `prometheus-source` tree on this branch. The
harness that drives that corpus — `prometheus xbow run` — lands in
the same change as the deletion of the planted README. Until the
harness has been run end-to-end at least once, the honest number is
**0/0 solved**, not 96%.

## Run the benchmark

```bash
# Smoke test: list the curated pilot challenges (no docker side-effects)
PYTHONPATH=. python -m prometheus.interface.main xbow list

# Run a single challenge as a smoke test
PYTHONPATH=. python -m prometheus.interface.main xbow run --ids XBEN-001-24 --concurrency 1

# Run the full 5-challenge pilot
PYTHONPATH=. python -m prometheus.interface.main xbow run \
    --ids XBEN-001-24,XBEN-002-24,XBEN-003-24,XBEN-050-24,XBEN-100-24 \
    --concurrency 4

# Or, equivalently, via the convenience script:
./scripts/xbow_run.sh list
./scripts/xbow_run.sh run --ids XBEN-001-24,XBEN-050-24 --concurrency 2

# Generate a report from a prior run
PYTHONPATH=. python -m prometheus.interface.main xbow report <run_id>
```

Reports are written to `~/.prometheus/eval/xbow/<run_id>/report.md`
and the raw row data to `results.jsonl` in the same directory.

## What the harness does

1. Clones `https://github.com/xbow-engineering/validation-benchmarks`
   into `~/.prometheus/eval/xbow/xbow/` (shallow clone, cached).
2. For each challenge id, generates a unique flag
   `FLAG{XBEN-<id>-<uuid4>}` and runs `make build` inside the
   challenge dir, which sets the `FLAG` build-arg baked into the
   docker image.
3. Brings the challenge up with `docker compose up -d --wait`,
   binding a host port (`18001`–`18100`) on `127.0.0.1`.
4. Launches prometheus in a subprocess against
   `http://127.0.0.1:<port>`, with `--non-interactive` and a fresh
   per-challenge engagement folder under
   `~/.prometheus/engagements/<challenge-id>/`.
5. After the run, the flag-watcher searches the agent's
   `vulnerabilities.json`, `evidence/*.txt`, and the comms
   `status.jsonl` stream for the injected flag string. A match
   counts as solved.
6. Tears the container down (`docker stop && docker rm`); a
   `try/finally` in the harness guarantees cleanup even if
   prometheus crashes.
7. Appends a row to `~/.prometheus/eval/xbow/<run_id>/results.jsonl`
   and renders a `report.md` with per-challenge pass/fail, duration,
   token cost, and an aggregate "X/5 solved, mean Ym" line.

The harness reuses the existing `prometheus/eval/__init__.py`
shapes (`EvalChallenge` / `EvalResult` / `run_eval`) and mirrors them
as `XBOWChallenge` / `XBOWResult` / `run_xbow`. It does not modify
the existing Juice Shop / PortSwigger mock oracle; the two harnesses
are independent.
