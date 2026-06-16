"""XBOW runner — ``prometheus xbow {list,run,report}`` subcommands.

Design points (per the plan):

* Each challenge gets its own subprocess invocation of the
  ``prometheus`` CLI with ``--target http://127.0.0.1:<port>`` and
  ``--non-interactive``. Subprocess, not in-process, so each run
  has a fresh docker sandbox + a fresh LLM warm-up; failure of one
  challenge does not pollute the next.
* Per-challenge engagement folder is created up front under
  ``~/.prometheus/engagements/<challenge-id>/`` so the agent has
  scope guardrails and the engine.log/evidence/ state surfaces.
* ``--concurrency N`` bounds the number of challenges running at
  once via :func:`prometheus.eval.xbow.concurrency.bounded_gather`.
* The harness never touches ``create_vulnerability_report`` against
  HackerOne / Bugcrowd / any real bounty platform — the engine.log
  records "Do not auto-submit" and the only write target is the
  XBOW results store.
* The harness is additive to the existing
  ``prometheus.eval.EvalChallenge`` oracle; the new types are
  ``XBOWChallenge`` / ``XBOWResult`` / ``run_xbow``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from prometheus.eval.xbow.challenges import PILOT, XBOWChallenge, resolve
from prometheus.eval.xbow.concurrency import bounded_gather
from prometheus.eval.xbow.flag_watch import FlagWatchResult, watch as flag_watch
from prometheus.eval.xbow.loader import (
    build_challenge,
    discover_host_port,
    fetch_challenge,
    generate_unique_flag,
    start_challenge,
    stop_challenge,
)
from prometheus.eval.xbow.results import (
    DEFAULT_ROOT,
    XBOWResult,
    append_row,
    make_run_id,
    run_dir,
    write_report,
)

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Subcommand: list
# ----------------------------------------------------------------------
def _cmd_list(_args: argparse.Namespace) -> int:
    print(f"{'id':<14} {'L':<2} {'port':<6} {'tags':<32} description")
    print("-" * 90)
    for ch in PILOT:
        print(
            f"{ch.id:<14} {ch.level:<2} {ch.host_port:<6} {','.join(ch.tags):<32} {ch.description}"
        )
    print()
    print(f"{len(PILOT)} challenges in the curated pilot. Use --ids to pick a subset.")
    return 0


# ----------------------------------------------------------------------
# Subcommand: report
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

    rows: list[XBOWResult] = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"Skipping corrupt row: {exc}", file=sys.stderr)
            continue
        rows.append(XBOWResult(**d))

    out = target / "report.md"
    write_report(rows, out, run_id=args.run_id)
    print(f"Rendered {out}")
    if rows:
        passed = sum(1 for r in rows if r.passed)
        print(f"Score: {passed}/{len(rows)}")
    return 0


# ----------------------------------------------------------------------
# Subcommand: run
# ----------------------------------------------------------------------
def _make_engagement(challenge_id: str) -> Path:
    """Create ``~/.prometheus/engagements/<id>/`` if missing.

    Imports the engagement manager lazily so ``prometheus xbow list``
    works even if engagement scaffolding isn't available yet (e.g.,
    running the harness inside a fresh container).
    """
    try:
        from prometheus.engagement.manager import DEFAULT_ENGAGEMENTS_ROOT, Engagement  # type: ignore
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Engagement module not available: %s", exc)
        root = Path.home() / ".prometheus" / "engagements" / challenge_id
        root.mkdir(parents=True, exist_ok=True)
        (root / "evidence").mkdir(exist_ok=True)
        (root / "runs").mkdir(exist_ok=True)
        return root

    eng_root = DEFAULT_ENGAGEMENTS_ROOT / challenge_id
    if not eng_root.is_dir() or not (eng_root / "state.json").is_file():
        try:
            Engagement.create(challenge_id, overwrite=False)
        except Exception as exc:
            logger.warning(
                "Engagement.create(%s) failed (%s); using bare folder",
                challenge_id,
                exc,
            )
            eng_root.mkdir(parents=True, exist_ok=True)
            (eng_root / "evidence").mkdir(exist_ok=True)
            (eng_root / "runs").mkdir(exist_ok=True)

    # Append a sentinel line to engine.log so an audit can later tell
    # the XBOW harness was here.
    log = eng_root / "engine.log"
    sentinel = (
        f"\n# {datetime.now(UTC).isoformat()} — prometheus xbow run start\n"
        f"# Do not auto-submit. This engagement is a benchmark run, not a real bug-bounty engagement.\n"
    )
    with log.open("a", encoding="utf-8") as f:
        f.write(sentinel)

    return eng_root


def _run_prometheus(
    *,
    target: str,
    engagement_name: str,
    timeout_s: int,
) -> subprocess.CompletedProcess:
    """Launch the prometheus CLI as a subprocess against ``target``."""
    repo_root = _prometheus_source_root()
    cmd = [
        sys.executable,
        "-m",
        "prometheus.interface.main",
        "-t",
        target,
        "-n",  # non-interactive
        "--run-name",
        engagement_name,
        "--rate-limit",
        "10",
    ]
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(repo_root))
    logger.info("Launching prometheus subprocess: %s", " ".join(shlex.quote(c) for c in cmd))
    return subprocess.run(
        cmd,
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _prometheus_source_root() -> Path:
    """Return the prometheus source root (where ``pyproject.toml`` lives)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (
            parent / "prometheus" / "interface" / "main.py"
        ).is_file():
            return parent
    # Fallback: assume cwd is the source root.
    return Path.cwd()


async def _run_one(
    ch: XBOWChallenge,
    *,
    dest_root: Path,
    per_challenge_timeout: int,
) -> XBOWResult:
    """Build → start → launch prometheus → flag-watch → tear down.

    Always tears the challenge down in a ``finally`` block. Returns
    an :class:`XBOWResult` for the row writer; the caller never sees
    a raw exception (one bad challenge should not abort the run).
    """
    started = datetime.now(UTC)
    flag = generate_unique_flag(ch.id)
    run_id = ""
    container_id = ""
    error = ""
    watch_result: FlagWatchResult | None = None
    prom_proc: subprocess.CompletedProcess | None = None

    # 1. Scaffold the engagement folder so the agent has scope.
    try:
        engagement_root = _make_engagement(ch.id)
    except Exception as exc:  # noqa: BLE001
        return XBOWResult(
            challenge_id=ch.id,
            level=ch.level,
            tags=list(ch.tags),
            passed=False,
            duration_s=0.0,
            host_port=ch.host_port,
            error=f"engagement scaffold: {exc!r}",
            started_at=started.isoformat(),
            finished_at=datetime.now(UTC).isoformat(),
        )

    start = time.monotonic()
    challenge_dir: Path | None = None
    host_port: int = 0
    try:
        # 2. Ensure repo + build + start.
        challenge_dir = fetch_challenge(ch.id, dest_root)
        build_challenge(challenge_dir, flag, timeout=per_challenge_timeout)
        container_id = start_challenge(challenge_dir, timeout=per_challenge_timeout)

        # 3. Discover the actual host port the challenge is on
        #    (XBOW mixes `ports: - 80` ephemeral binds with
        #    `ports: - "5000:5000"` fixed binds; we read the live
        #    mapping rather than guessing).
        try:
            host_port = discover_host_port(challenge_dir, internal_port=80)
        except Exception as exc:  # noqa: BLE001
            # Most common cause: the primary service listens on 5000
            # not 80. Try the second most common.
            try:
                host_port = discover_host_port(challenge_dir, internal_port=5000)
            except Exception as exc2:  # noqa: BLE001
                raise RuntimeError(
                    f"Could not discover host port for {ch.id}: {exc!r} / {exc2!r}"
                ) from exc2
        target = f"http://127.0.0.1:{host_port}"

        # 4. Run prometheus against the live target.
        try:
            _prom_proc = _run_prometheus(  # noqa: F841  — kept for diagnostic logging
                target=target,
                engagement_name=ch.id,
                timeout_s=per_challenge_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            error = f"prometheus timed out after {per_challenge_timeout}s"
            logger.warning("%s: %s", ch.id, error)
            _prom_proc = None  # type: ignore[assignment]
        except Exception as exc:  # noqa: BLE001
            error = f"prometheus launch failed: {exc!r}"
            logger.warning("%s: %s", ch.id, error)

        # 4. Try to recover the prometheus run id from the engagement
        #    state.json (it carries a per-engagement run counter).
        run_id = ch.id
        try:
            state_path = engagement_root / "state.json"
            if state_path.is_file():
                d = json.loads(state_path.read_text(encoding="utf-8"))
                if isinstance(d, dict) and d.get("last_run_id"):
                    run_id = str(d["last_run_id"])
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Could not read engagement state: %s", exc)

        # 5. Flag watch.
        watch_result = flag_watch(
            flag,
            engagement_dir=engagement_root,
            run_id=run_id,
            challenge_dir=challenge_dir,
        )

    except Exception as exc:  # noqa: BLE001 - eval harness must be defensive
        error = f"harness exception: {exc!r}"
        logger.exception("XBOW challenge %s failed: %s", ch.id, exc)
    finally:
        # 6. Tear down no matter what.
        if challenge_dir is not None and container_id:
            try:
                stop_challenge(challenge_dir, container_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("teardown of %s raised: %s", ch.id, exc)

    duration = time.monotonic() - start
    vuln_count = 0
    try:
        vjson = engagement_root / "vulnerabilities.json"
        if vjson.is_file():
            rows = json.loads(vjson.read_text(encoding="utf-8"))
            if isinstance(rows, list):
                vuln_count = len(rows)
    except (OSError, json.JSONDecodeError):
        logger.debug(
            "could not read vulnerabilities.json for challenge %s, vuln_count=0",
            ch.id,
            exc_info=True,
        )

    return XBOWResult(
        challenge_id=ch.id,
        level=ch.level,
        tags=list(ch.tags),
        passed=bool(watch_result and watch_result.passed),
        duration_s=duration,
        host_port=ch.host_port,
        container_id=container_id[:12] if container_id else "",
        run_id=run_id,
        vuln_count=vuln_count,
        notes=(
            f"target=http://127.0.0.1:{host_port}; "
            + (
                watch_result.last_vuln_titles[0]
                if watch_result and watch_result.last_vuln_titles
                else ""
            )
        ),
        snippet=watch_result.snippet if watch_result else "",
        match_path=watch_result.match_path if watch_result else "",
        container_flag_visible=(watch_result.container_flag_visible if watch_result else ""),
        error=error,
        started_at=started.isoformat(),
        finished_at=datetime.now(UTC).isoformat(),
        target=f"http://127.0.0.1:{host_port}",
    )


def _cmd_run(args: argparse.Namespace) -> int:
    # ``--ids`` defaults to "" in argparse; main() rewrites that to
    # the full pilot before we get here. Treat empty defensively.
    if not args.ids:
        args.ids = ",".join(ch.id for ch in PILOT)
    if not args.ids:
        print("No challenge ids supplied. Use --ids XBEN-001-24,...", file=sys.stderr)
        return 2
    try:
        challenges = resolve(args.ids.split(",") if isinstance(args.ids, str) else args.ids)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    dest_root = (
        Path(args.dest_root) if args.dest_root else Path.home() / ".prometheus" / "eval" / "xbow"
    )
    dest_root.mkdir(parents=True, exist_ok=True)

    run_id = args.run_id or make_run_id()
    rdir = run_dir(run_id, root=dest_root)
    jsonl = rdir / "results.jsonl"

    print(f"XBOW run: {run_id}")
    print(f"  challenges : {len(challenges)}")
    print(f"  concurrency: {args.concurrency}")
    print(f"  per-challenge timeout: {args.timeout}s")
    print(f"  results    : {jsonl}")
    print(f"  report     : {rdir / 'report.md'}")
    print()

    async def _drive() -> list[XBOWResult]:
        coros = [
            _run_one(
                ch,
                dest_root=dest_root,
                per_challenge_timeout=args.timeout,
            )
            for ch in challenges
        ]
        return await bounded_gather(coros, n=args.concurrency)  # type: ignore[return-value]

    raw: list[XBOWResult | Exception] = asyncio.run(_drive())
    rows: list[XBOWResult] = []
    for ch, item in zip(challenges, raw):
        if isinstance(item, Exception):
            rows.append(
                XBOWResult(
                    challenge_id=ch.id,
                    level=ch.level,
                    tags=list(ch.tags),
                    passed=False,
                    duration_s=0.0,
                    host_port=ch.host_port,
                    error=f"gather exception: {item!r}",
                    started_at=datetime.now(UTC).isoformat(),
                    finished_at=datetime.now(UTC).isoformat(),
                )
            )
        else:
            rows.append(item)
        append_row(rows[-1], jsonl)
        verdict = "✅" if rows[-1].passed else "❌"
        print(
            f"  {verdict}  {rows[-1].challenge_id}  {rows[-1].duration_s:6.1f}s   {rows[-1].error or rows[-1].notes}"
        )

    out = rdir / "report.md"
    write_report(rows, out, run_id=run_id)
    passed = sum(1 for r in rows if r.passed)
    print()
    print(f"Score: {passed}/{len(rows)}  (see {out})")
    return 0


# ----------------------------------------------------------------------
# argparse
# ----------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus xbow",
        description="XBOW validation-benchmarks harness for prometheus.",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_list = sub.add_parser("list", help="List the curated pilot challenges")
    p_list.set_defaults(func=_cmd_list)

    p_run = sub.add_parser("run", help="Run one or more challenges")
    p_run.add_argument(
        "--ids",
        type=str,
        default="",
        help="Comma-separated challenge ids (e.g. XBEN-001-24,XBEN-050-24). "
        "Default: the full pilot.",
    )
    p_run.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Max number of challenges running at once (default 4).",
    )
    p_run.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Per-challenge wall-clock cap in seconds (default 900 = 15 min).",
    )
    p_run.add_argument(
        "--dest-root",
        type=str,
        default="",
        help="Where the harness stores results (default ~/.prometheus/eval/xbow).",
    )
    p_run.add_argument(
        "--run-id",
        type=str,
        default="",
        help="Reuse an existing run id; useful for resuming a partial run.",
    )
    p_run.set_defaults(func=_cmd_run)

    p_rep = sub.add_parser("report", help="Re-render report.md for a prior run")
    p_rep.add_argument("run_id", help="Run id (the subfolder under ~/.prometheus/eval/xbow)")
    p_rep.add_argument(
        "--root",
        type=str,
        default="",
        help="Override the eval root (default ~/.prometheus/eval/xbow).",
    )
    p_rep.set_defaults(func=_cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point — ``prometheus xbow <list|run|report>``."""
    logging.basicConfig(
        level=os.environ.get("XBOW_LOG", "INFO"),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # Default: list
        return _cmd_list(args)
    # Default: ``--ids`` is empty string; the run subcommand treats
    # that as "use the full pilot".
    if args.cmd == "run" and not args.ids:
        args.ids = ",".join(ch.id for ch in PILOT)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
