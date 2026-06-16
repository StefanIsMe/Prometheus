"""RealVuln-Benchmark runner — ``prometheus realvuln {list, run, report, score}``.

Subprocesses prometheus against each of 26 target repos and writes
Semgrep-shaped results to the benchmark's ``scan-results/{repo}/<slug>/``
directory. Then invokes the benchmark's ``score.py`` to compute F2.

Mirrors the layout of ``prometheus.eval.xbow.runner`` — same
async+subprocess dance, same JSONL row store, same report.md render.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from prometheus.eval.xbow.concurrency import bounded_gather

from .challenges import (
    REPO_SLUGS,
    SCAN_RESULTS_DIR,
    SCANNER_SLUG,
    RepoMeta,
    fetch_ground_truth,
    iter_repos,
)
from .loader import fetch_target_repo, verify_pinned
from .normalizer import build_results_doc
from .results import (
    DEFAULT_ROOT,
    RealVulnResult,
    append_row,
    make_run_id,
    report_from_jsonl,
    run_dir,
    write_report,
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# paths
# ----------------------------------------------------------------------

_INSTRUCTION_FILE = Path(__file__).parent / "instruction.md"

# A dedicated runs-root for the realvuln harness so we don't pollute
# the user's main `~/.../prometheus_runs/` tree, and so the harness
# can glob the latest per-repo subdirs deterministically.
_REALVULN_RUNS_ROOT = Path.home() / ".prometheus" / "realvuln_prometheus_runs"
_REALVULN_RUNS_ROOT.mkdir(parents=True, exist_ok=True)


def _prometheus_source_root() -> Path:
    """Where pyproject.toml lives — used to set PYTHONPATH for the subprocess."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (
            parent / "prometheus" / "interface" / "main.py"
        ).is_file():
            return parent
    return Path.cwd()


# ----------------------------------------------------------------------
# subprocess: prometheus per repo
# ----------------------------------------------------------------------


def _run_prometheus(
    *,
    target_dir: Path,
    run_name: str,
    timeout_s: int,
) -> subprocess.CompletedProcess:
    """Invoke the prometheus CLI on a local code target.

    Mirrors ``prometheus.eval.xbow.runner._run_prometheus`` but with
    a directory target and ``--scope-mode full`` so PR diff-scope
    is not applied.

    Note: there is no ``--run-name`` flag on the prometheus CLI —
    the run name is auto-generated from the target. We pin the
    runs dir via ``PROMETHEUS_RUNS_DIR`` and read the latest
    subdir back via :func:`_find_latest_vulnerabilities_json`.
    """
    repo_root = _prometheus_source_root()
    cmd = [
        sys.executable,
        "-m",
        "prometheus.interface.main",
        "-t",
        str(target_dir),
        "-n",  # non-interactive
        "--scope-mode",
        "full",
        "--instruction-file",
        str(_INSTRUCTION_FILE),
        "--rate-limit",
        "10",
    ]
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(repo_root))
    env["PROMETHEUS_RUNS_DIR"] = str(_REALVULN_RUNS_ROOT)
    # On this machine, prometheus/scripts/ is missing; the sandbox
    # requires that path for scan-pipeline.sh. Point it at the
    # top-level scripts/ dir which exists.
    env.setdefault("PROMETHEUS_SCRIPTS_DIR", str(_prometheus_source_root() / "scripts"))
    logger.info("Launching: %s (run_name=%s)", " ".join(shlex.quote(c) for c in cmd), run_name)
    return subprocess.run(
        cmd,
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


# ----------------------------------------------------------------------
# score.py invocation
# ----------------------------------------------------------------------


def _run_score(
    *,
    repo_slug: str,
    run_artifacts_dir: Path,
    timeout_s: int = 60,
) -> dict[str, Any]:
    """Invoke RealVuln's ``score.py`` for one repo and return the metric dict.

    We invoke it from the benchmark repo's cwd so ``ground-truth/`` and
    ``scan-results/`` resolve relative paths the way score.py expects.
    Captures the JSON output via ``--json-out`` (if the upstream
    supports it) or by parsing the human-readable stdout; falls back
    to an empty dict on any failure.
    """
    from .challenges import BENCHMARK_REPO_DIR

    scorecard = run_artifacts_dir / f"{repo_slug}.scorecard.json"
    cmd = [
        sys.executable,
        "score.py",
        "--repo",
        repo_slug,
        "--scanner",
        SCANNER_SLUG,
        "--all-scanners",  # no-op if only one is present; keeps the call future-proof
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(BENCHMARK_REPO_DIR),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("score.py failed for %s: %s", repo_slug, exc)
        return {}

    if proc.returncode != 0:
        logger.warning(
            "score.py for %s returned %d: stderr=%s",
            repo_slug,
            proc.returncode,
            proc.stderr[-500:],
        )
        return _parse_score_stdout(proc.stdout, repo_slug=repo_slug, scorecard=scorecard)

    return _parse_score_stdout(proc.stdout, repo_slug=repo_slug, scorecard=scorecard)


_METRIC_RE = re.compile(
    r"(?P<key>precision|recall|f1|f2|f2_score|fpr|true_positives?|false_positives?|false_negatives?|true_negatives?)\s*[:=]\s*(?P<val>[-+]?\d*\.?\d+)",
    re.IGNORECASE,
)

# Normalise upstream's metric names -> our dataclass fields.
_NAME_MAP = {
    "precision": "precision",
    "recall": "recall",
    "f1": "f1",
    "f2": "f2",
    "f2_score": "f2",
    "fpr": "fpr",
    "true_positive": "tp",
    "true_positives": "tp",
    "false_positive": "fp",
    "false_positives": "fp",
    "false_negative": "fn",
    "false_negatives": "fn",
    "true_negative": "tn",
    "true_negatives": "tn",
}


def _parse_score_stdout(stdout: str, *, repo_slug: str, scorecard: Path) -> dict[str, Any]:
    """Pull the per-repo numbers out of score.py's text output.

    RealVuln's score.py writes a per-repo markdown scorecard. The
    tabular block has lines like ``F2: 0.730`` and ``TP: 12``. We
    scrape those, persist the raw stdout for the report, and return
    a flat dict ready to merge into the row.
    """
    out: dict[str, Any] = {}
    for m in _METRIC_RE.finditer(stdout):
        key = _NAME_MAP.get(m.group("key").lower())
        if not key:
            continue
        try:
            out[key] = float(m.group("val"))
        except ValueError:
            continue
    # Integers for the counts.
    for k in ("tp", "fp", "fn", "tn"):
        if k in out:
            out[k] = int(out[k])

    # Persist what we got so the report can quote it.
    try:
        scorecard.write_text(
            json.dumps({"slug": repo_slug, "stdout": stdout, "parsed": out}, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        logger.debug("Could not write scorecard for %s: %s", repo_slug, exc)

    return out


# ----------------------------------------------------------------------
# one-repo coroutine
# ----------------------------------------------------------------------


async def _run_one(
    meta: RepoMeta,
    *,
    run_id: str,
    runs_n: int,
    per_repo_timeout: int,
    dest_root: Path,
) -> RealVulnResult:
    """Clone → pin → invoke prometheus N times → write results → score."""
    started = datetime.now(UTC)
    err = ""
    prom_vuln_count = 0
    prom_ran = False
    flat_results: list[dict[str, Any]] = []

    # 1. clone + pin target
    target_dir: Path | None = None
    try:
        target_dir = fetch_target_repo(meta.slug, meta.repo_url, meta.commit_sha)
        if not verify_pinned(target_dir, meta.commit_sha):
            raise RuntimeError(f"could not pin to {meta.commit_sha[:8]}")
    except Exception as exc:  # noqa: BLE001
        return RealVulnResult(
            repo_slug=meta.slug,
            total_vulns=meta.total_vulns,
            total_traps=meta.total_traps,
            prom_vuln_count=0,
            prom_ran=False,
            duration_s=0.0,
            run_id=run_id,
            error=f"clone/pin: {exc!r}",
            started_at=started.isoformat(),
            finished_at=datetime.now(UTC).isoformat(),
        )

    # 2. invoke prometheus N times, accumulate findings
    run_artifacts_dir = run_dir(run_id, root=dest_root)
    score_metrics: dict[str, Any] = {}
    start = time.monotonic()

    for run_idx in range(1, runs_n + 1):
        # We pass run_name to the subprocess env so we can locate the
        # produced artifacts; prometheus itself auto-generates the
        # actual run-name from the target (e.g. ``<slug>_<hex>``).
        run_name = f"realvuln-{meta.slug}-r{run_idx}"
        try:
            proc = _run_prometheus(
                target_dir=target_dir,
                run_name=run_name,
                timeout_s=per_repo_timeout,
            )
        except subprocess.TimeoutExpired:
            err = f"prometheus timed out after {per_repo_timeout}s on run {run_idx}"
            logger.warning("%s: %s", meta.slug, err)
            break
        except Exception as exc:  # noqa: BLE001
            err = f"prometheus launch failed: {exc!r}"
            logger.warning("%s: %s", meta.slug, err)
            break

        if proc.returncode != 0:
            err = f"prometheus rc={proc.returncode} on run {run_idx}: {proc.stderr[-200:]}"
            logger.warning("%s: %s", meta.slug, err)
            # Continue — earlier runs may have produced findings.

        # 3. find the actual run dir that prometheus produced and read
        #    vulnerabilities.json from it. We glob the latest subdir
        #    in our dedicated runs root (newer than the run start).
        actual_vjson = _find_latest_vulnerabilities_json(started_at=started)
        if actual_vjson is not None and actual_vjson.is_file():
            try:
                rows = json.loads(actual_vjson.read_text(encoding="utf-8"))
                # vulnerabilities.json is a list of findings, but the
                # prometheus_findings_to_flat helper defends against
                # unexpected envelopes (dict, etc.).
                flat = prometheus_findings_to_flat(rows)
                if not flat and isinstance(rows, list):
                    flat = [r for r in rows if isinstance(r, dict)]
                prom_vuln_count += len(flat)
                flat_results.extend(flat)
                prom_ran = True
                logger.info(
                    "%s: read %d findings from %s",
                    meta.slug,
                    len(flat),
                    actual_vjson,
                )
            except (OSError, json.JSONDecodeError) as exc:
                err = f"vulnerabilities.json read failed: {exc!r}"
                logger.warning("%s: %s", meta.slug, err)
        else:
            err = f"vulnerabilities.json missing for run {run_idx}"
            logger.info("%s: %s (rc=%d)", meta.slug, err, proc.returncode)

        # Write a per-run results.json in the benchmark's layout.
        doc = build_results_doc(flat_results, scanner_slug=SCANNER_SLUG)
        out_dir = SCAN_RESULTS_DIR / meta.slug / SCANNER_SLUG
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"run-{run_idx}.json").write_text(
            json.dumps(doc, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    duration = time.monotonic() - start

    # 4. score (only if at least one run produced output)
    if prom_ran:
        score_metrics = _run_score(
            repo_slug=meta.slug,
            run_artifacts_dir=run_artifacts_dir,
        )
        if not score_metrics and not err:
            err = "score.py produced no parseable metrics"

    finished = datetime.now(UTC)
    return RealVulnResult(
        repo_slug=meta.slug,
        total_vulns=meta.total_vulns,
        total_traps=meta.total_traps,
        prom_vuln_count=prom_vuln_count,
        prom_ran=prom_ran,
        duration_s=duration,
        run_id=run_id,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        error=err,
        **score_metrics,
    )


def prometheus_findings_to_flat(v: Any) -> list[dict[str, Any]]:
    """Defensive: vulnerabilities.json is a list, but defend against dict-wrapped."""
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    if isinstance(v, dict):
        # Some legacy versions wrap the array in a {"findings": [...]} envelope.
        for key in ("findings", "vulnerabilities", "results", "items"):
            inner = v.get(key)
            if isinstance(inner, list):
                return [x for x in inner if isinstance(x, dict)]
    return []


def run_dir_for_run(run_name: str) -> Path:
    """Find the on-disk prometheus run dir for ``run_name``.

    Since the harness pins ``PROMETHEUS_RUNS_DIR`` to
    ``~/.prometheus/realvuln_prometheus_runs/``, this is the one
    location we need to look in.
    """
    candidate = _REALVULN_RUNS_ROOT / "prometheus_runs" / run_name / "vulnerabilities.json"
    if candidate.is_file():
        return candidate
    return candidate  # sentinel — missing


def _find_latest_vulnerabilities_json(*, started_at: datetime) -> Path | None:
    """Return the newest vulnerabilities.json produced after ``started_at``.

    Prometheus auto-generates the run-name from the target (e.g.
    ``pythonssti_<hex>``); we don't try to predict it. Instead we
    look for any run dir under our dedicated runs root whose mtime
    is after we kicked off the subprocess and pick the newest.
    """
    runs_root = _REALVULN_RUNS_ROOT / "prometheus_runs"
    if not runs_root.is_dir():
        return None
    candidates: list[tuple[float, Path]] = []
    for run_dir in runs_root.iterdir():
        if not run_dir.is_dir():
            continue
        vjson = run_dir / "vulnerabilities.json"
        if not vjson.is_file():
            continue
        try:
            mtime = vjson.stat().st_mtime
        except OSError:
            continue
        if mtime >= started_at.timestamp() - 1:  # 1s slop
            candidates.append((mtime, vjson))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


# ----------------------------------------------------------------------
# subcommand: list
# ----------------------------------------------------------------------


def _cmd_list(_args: argparse.Namespace) -> int:
    rows = list(iter_repos())
    if not rows:
        print("No repos loaded. Is the benchmark cloned?")
        return 1
    print(f"{'slug':<48} {'vulns':>6} {'traps':>6} {'framework':<14} {'loc':>8}  commit")
    print("-" * 110)
    for m in sorted(rows, key=lambda r: -r.total_vulns):
        fw = m.framework or "—"
        loc = m.loc or 0
        print(
            f"{m.slug:<48} {m.total_vulns:>6} {m.total_traps:>6} {fw:<14} {loc:>8}  {m.commit_sha[:8]}"
        )
    print()
    print(
        f"{len(rows)} repos. Total vulns: {sum(r.total_vulns for r in rows)}  traps: {sum(r.total_traps for r in rows)}"
    )
    return 0


# ----------------------------------------------------------------------
# subcommand: run
# ----------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    fetch_ground_truth()
    slugs = [s.strip() for s in (args.repos or "").split(",") if s.strip()] or REPO_SLUGS
    metas_by_slug: dict[str, RepoMeta] = {m.slug: m for m in iter_repos(slugs)}
    if not metas_by_slug:
        print("No valid repos in --repos", file=sys.stderr)
        return 2
    ordered = [metas_by_slug[s] for s in slugs if s in metas_by_slug]

    dest_root = Path(args.dest_root) if args.dest_root else DEFAULT_ROOT
    dest_root.mkdir(parents=True, exist_ok=True)
    run_id = args.run_id or make_run_id()
    rdir = run_dir(run_id, root=dest_root)
    jsonl = rdir / "results.jsonl"

    # Reset JSONL if this is a fresh run id.
    if not args.run_id and jsonl.exists():
        jsonl.unlink()

    print(f"RealVuln run: {run_id}")
    print(f"  repos        : {len(ordered)}")
    print(f"  runs/repo    : {args.runs}")
    print(f"  concurrency  : {args.concurrency}")
    print(f"  per-repo cap : {args.timeout}s")
    print(f"  scanner slug : {SCANNER_SLUG}")
    print(f"  results      : {jsonl}")
    print(f"  report       : {rdir / 'report.md'}")
    print(f"  scan results : {SCAN_RESULTS_DIR}")
    print()

    async def _drive() -> list[Any]:
        coros = [
            _run_one(
                m,
                run_id=run_id,
                runs_n=args.runs,
                per_repo_timeout=args.timeout,
                dest_root=dest_root,
            )
            for m in ordered
        ]
        return await bounded_gather(coros, n=args.concurrency)

    raw = asyncio.run(_drive())
    rows: list[RealVulnResult] = []
    for meta, item in zip(ordered, raw):
        if isinstance(item, BaseException):
            rows.append(
                RealVulnResult(
                    repo_slug=meta.slug,
                    total_vulns=meta.total_vulns,
                    total_traps=meta.total_traps,
                    prom_vuln_count=0,
                    prom_ran=False,
                    duration_s=0.0,
                    run_id=run_id,
                    error=f"gather exception: {item!r}",
                    started_at=datetime.now(UTC).isoformat(),
                    finished_at=datetime.now(UTC).isoformat(),
                )
            )
        elif isinstance(item, RealVulnResult):
            rows.append(item)
        else:  # defensive
            rows.append(
                RealVulnResult(
                    repo_slug=meta.slug,
                    total_vulns=meta.total_vulns,
                    total_traps=meta.total_traps,
                    prom_vuln_count=0,
                    prom_ran=False,
                    duration_s=0.0,
                    run_id=run_id,
                    error=f"unexpected return: {item!r}",
                )
            )
        append_row(rows[-1], jsonl)
        verdict = "✅" if rows[-1].prom_ran and not rows[-1].error else "❌"
        print(
            f"  {verdict}  {rows[-1].repo_slug:<48} "
            f"{rows[-1].prom_vuln_count:>3} findings  "
            f"F2={rows[-1].f2:.3f}  "
            f"{rows[-1].duration_s:6.1f}s  "
            f"{rows[-1].error or ''}"
        )

    out = rdir / "report.md"
    write_report(rows, out, run_id=run_id)
    print()
    print(
        f"Score: {sum(1 for r in rows if r.prom_ran and not r.error)}/{len(rows)} repos produced findings."
    )
    print(f"Report: {out}")
    return 0


# ----------------------------------------------------------------------
# subcommand: report
# ----------------------------------------------------------------------


def _cmd_report(args: argparse.Namespace) -> int:
    base = Path(args.root) if args.root else DEFAULT_ROOT
    target = base / args.run_id
    if not target.is_dir():
        print(f"No run found at {target}", file=sys.stderr)
        return 1
    jsonl = target / "results.jsonl"
    if not jsonl.is_file():
        print(f"No results.jsonl at {jsonl}", file=sys.stderr)
        return 1
    out = target / "report.md"
    report_from_jsonl(jsonl, out, run_id=args.run_id)
    print(f"Rendered {out}")
    return 0


# ----------------------------------------------------------------------
# subcommand: score  (re-invoke score.py only, no prometheus runs)
# ----------------------------------------------------------------------


def _cmd_score(args: argparse.Namespace) -> int:
    fetch_ground_truth()
    slugs = [s.strip() for s in (args.repos or "").split(",") if s.strip()] or REPO_SLUGS
    metas_by_slug: dict[str, RepoMeta] = {m.slug: m for m in iter_repos(slugs)}
    if not metas_by_slug:
        print("No valid repos in --repos", file=sys.stderr)
        return 2
    ordered = [metas_by_slug[s] for s in slugs if s in metas_by_slug]

    dest_root = Path(args.dest_root) if args.dest_root else DEFAULT_ROOT
    run_id = args.run_id or "rescore"
    rdir = run_dir(run_id, root=dest_root)
    jsonl = rdir / "results.jsonl"

    # Re-score: re-invoke score.py per repo, but we can't recover TP/FP
    # from a previous run if it wasn't recorded. So we require --reuses
    # the existing jsonl when present.
    existing: dict[str, RealVulnResult] = {}
    if jsonl.is_file():
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                r = RealVulnResult(**d)
                existing[r.repo_slug] = r
            except TypeError:
                continue

    print(f"Re-scoring {len(ordered)} repos under run id '{run_id}'")
    rows: list[RealVulnResult] = []
    for meta in ordered:
        prior = existing.get(meta.slug) or RealVulnResult(
            repo_slug=meta.slug,
            total_vulns=meta.total_vulns,
            total_traps=meta.total_traps,
            prom_vuln_count=0,
            prom_ran=False,
            duration_s=0.0,
            run_id=run_id,
        )
        metrics = _run_score(repo_slug=meta.slug, run_artifacts_dir=rdir)
        if metrics:
            for k, v in metrics.items():
                if hasattr(prior, k):
                    setattr(prior, k, v)
            prior.error = ""  # clear stale error if score now succeeded
        rows.append(prior)
        append_row(prior, jsonl)
        verdict = "✅" if prior.f2 or prior.prom_ran else "❌"
        print(
            f"  {verdict}  {prior.repo_slug:<48} F2={prior.f2:.3f}  P={prior.precision:.3f}  R={prior.recall:.3f}"
        )

    out = rdir / "report.md"
    write_report(rows, out, run_id=run_id)
    print()
    print(f"Report: {out}")
    return 0


# ----------------------------------------------------------------------
# argparse
# ----------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus realvuln",
        description="Run prometheus against the kolega-ai/Real-Vuln-Benchmark and produce F2 scores.",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="List the 26 target repos with vuln/trap counts")
    p_list.set_defaults(func=_cmd_list)

    p_run = sub.add_parser("run", help="Run prometheus against the requested repos")
    p_run.add_argument(
        "--repos",
        type=str,
        default="",
        help="Comma-separated repo slugs (default: all 26). Example: realvuln-pythonssti,realvuln-pygoat",
    )
    p_run.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of prometheus invocations per repo (each writes run-N.json). Default 1.",
    )
    p_run.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Max number of repos running prometheus at once (default 4).",
    )
    p_run.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Per-repo (and per-run) wall-clock cap in seconds (default 1800 = 30 min).",
    )
    p_run.add_argument(
        "--dest-root",
        type=str,
        default="",
        help="Where the harness stores results (default ~/.prometheus/eval/realvuln).",
    )
    p_run.add_argument(
        "--run-id",
        type=str,
        default="",
        help="Reuse an existing run id; useful for resuming a partial run.",
    )
    p_run.set_defaults(func=_cmd_run)

    p_rep = sub.add_parser("report", help="Re-render report.md for a prior run")
    p_rep.add_argument("run_id", help="Run id (the subfolder under ~/.prometheus/eval/realvuln)")
    p_rep.add_argument(
        "--root",
        type=str,
        default="",
        help="Override the eval root (default ~/.prometheus/eval/realvuln).",
    )
    p_rep.set_defaults(func=_cmd_report)

    p_score = sub.add_parser("score", help="Re-invoke score.py only (no prometheus runs)")
    p_score.add_argument(
        "--repos", type=str, default="", help="Comma-separated repo slugs (default: all 26)"
    )
    p_score.add_argument(
        "--run-id",
        type=str,
        default="rescore",
        help="Run id to record this re-score under (default: rescore).",
    )
    p_score.add_argument(
        "--dest-root",
        type=str,
        default="",
        help="Override the eval root (default ~/.prometheus/eval/realvuln).",
    )
    p_score.set_defaults(func=_cmd_score)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point — ``prometheus realvuln <list|run|report|score>``."""
    logging.basicConfig(
        level=os.environ.get("REALVULN_LOG", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        return _cmd_list(args)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
