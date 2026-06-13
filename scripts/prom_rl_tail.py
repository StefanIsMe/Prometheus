#!/usr/bin/env python3
"""prom_rl_tail.py — real-time visibility into a running prometheus scan.

The Prometheus scanner already writes a JSONL event stream to
``~/.prometheus/comms/<run_id>/status.jsonl`` via
``prometheus.core.comms.write_status``. This CLI consumes that stream and
renders it as dense, agent-readable lines.

The output format is optimized for AI ingestion (Claude, GPT, etc.): one
event per line, tab-separated ``time | event_type | key=value pairs``.
No ANSI, no progress bars, no decorative unicode. Use ``--human`` for
pretty colors.

Subcommands
-----------
list      List all known runs with status, finding count, last event.
status    One-shot dump of last 30 events + finding count. No following.
follow    Auto-attach to latest active run (or the given run_id) and
          stream events as they happen. Default subcommand.
events    Full JSONL dump (NDJSON) — one event per line, no rendering.

Examples
--------
    prom_rl_tail.py                       # follow the most recent run
    prom_rl_tail.py follow opensea-io_9ab5
    prom_rl_tail.py status
    prom_rl_tail.py status --filter finding
    prom_rl_tail.py list
    prom_rl_tail.py events | jq -c 'select(.type=="finding")'
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

COMMS_ROOT = Path.home() / ".prometheus" / "comms"

# Event-type -> (label, key=value extractor). The extractor receives the
# raw event dict and returns a list of (key, value) pairs to render.
# Keep the field set small and high-signal — the tailer is for visibility,
# not for replay. Full data is still in the JSONL (use `events` subcommand).
RENDERERS: dict[str, tuple[str, Any]] = {
    "scan_start": ("SCAN_START", lambda d: [
        ("target", (d.get("targets") or ["?"])[0]),
        ("mode", d.get("mode", "?")),
    ]),
    "scan_complete": ("SCAN_COMPLETE", lambda d: [
        ("status", d.get("status", "?")),
        ("findings", d.get("findings_count", d.get("findings", "?"))),
    ]),
    "turn_start": ("TURN_START", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("turn", d.get("turn", "?")),
    ]),
    "llm_call": ("LLM_CALL", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("model", d.get("model", "?")[-30:]),
        ("in", d.get("input_tokens", "?")),
        ("out", d.get("output_tokens", "?")),
        ("cache", d.get("cached_tokens", "?")),
    ]),
    "llm_message": ("LLM_MSG", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("model", d.get("model", "")[-12:]),
        ("text", d.get("text", "")[:120].replace("\n", " ")),
    ]),
    "thinking": ("THINK", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("model", d.get("model", "")[-12:]),
        ("vis", d.get("visible_chars", 0)),
        ("text", d.get("text", "")[:160].replace("\n", " ").replace("  ", " ")),
    ]),
    "tool_call": ("TOOL_CALL", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("tool", d.get("tool", "?")),
        ("args", d.get("args", d.get("command", ""))[:160].replace("\n", " ")),
    ]),
    "tool_call_stream": ("TOOL_CALL", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("tool", d.get("tool", "?")),
        ("args", d.get("args", "")[:160].replace("\n", " ")),
    ]),
    "tool_output": ("TOOL_OUTPUT", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("tool", d.get("tool", "?")),
        ("output", d.get("output", "")[:160].replace("\n", " ")),
    ]),
    "agent_spawn": ("AGENT_SPAWN", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("parent", (d.get("parent_id") or "?")[:8] if d.get("parent_id") else "-"),
        ("name", (d.get("name") or "?")[:40]),
        ("skills", ",".join(d.get("skills") or [])[:60]),
    ]),
    "agent_auto_respawn": ("AGENT_RESPAWN", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("name", (d.get("name") or "?")[:40]),
        ("attempt", d.get("attempt", "?")),
    ]),
    "agent_stall_detected": ("AGENT_STALL", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("name", (d.get("name") or "?")[:40]),
        ("idle_s", d.get("idle_seconds", "?")),
    ]),
    "finding": ("FINDING", lambda d: [
        ("severity", d.get("severity", "?")),
        ("endpoint", d.get("endpoint", d.get("url", ""))[:80]),
        ("title", d.get("title", d.get("description", ""))[:120]),
    ]),
    "finding_validated": ("FINDING", lambda d: [
        ("severity", d.get("severity", "?")),
        ("domain", d.get("domain", "")[:40]),
        ("endpoint", d.get("endpoint", "")[:80]),
        ("title", d.get("title", "")[:100]),
        ("lc", d.get("lifecycle", "?")),
    ]),
    "question": ("QUESTION", lambda d: [
        ("q", d.get("question", "")[:200]),
    ]),
    "instruction_received": ("INSTRUCTION", lambda d: [
        ("action", d.get("action", "?")),
        ("text", d.get("instruction", "")[:160]),
    ]),
    "scan_completed": ("SCAN_COMPLETE", lambda d: []),
    "agent_completed": ("AGENT_DONE", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
    ]),
    "gate_blocked": ("GATE_BLOCKED", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("gate", d.get("gate", "?")[:40]),
        ("tool", d.get("tool", "?")),
        ("refusals", d.get("consecutive_refusals", "?")),
        ("escape", "OPEN" if d.get("escape_hatch_open") else "no"),
    ]),
    "unfiled_claim": ("UNFILED", lambda d: [
        ("agent", (d.get("agent_id") or "?")[:8]),
        ("phrase", d.get("phrase", "?")[:30]),
        ("age", f"{d.get('age_s', '?')}s"),
        ("window", f"window={d.get('claim_window_s', '?')}s"),
        ("hint", d.get("hint", "")[:120]),
    ]),
}

UNKNOWN_LABEL = "EVENT"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _ts_to_hms(ts: str) -> str:
    """Parse a comms timestamp (ISO 8601) and return HH:MM:SS.mmm.

    Falls back to the first 12 chars if parsing fails, or '-' on error.
    """
    if not ts:
        return "-"
    try:
        # ISO format: 2026-06-13T01:23:45.123456+00:00
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
    except (ValueError, AttributeError):
        return ts[11:23] if len(ts) >= 23 else ts[:12]


# Default on-screen widths. The comms stream itself is untruncated;
# the tailer just decides how much to show per line so the output stays
# grep-able. --full disables the cap; --width N sets a custom one.
# Numbers are deliberately generous — security work is a place where
# "you should have caught that 404" matters. 200 chars showed only
# "HTTP/1.1 200 OK" and hid the 404 body that would have proven
# the agent's "critical finding" was a false positive.
DEFAULT_FIELD_WIDTHS = {
    "text": 200,
    "args": 200,
    "output": 320,
    "command": 200,
    "title": 160,
    "q": 240,
    "instruction": 200,
}
FULL_WIDTH = 10**9  # effectively unlimited
MIN_WIDTH = 40


def _cap(value: Any, key: str, widths: dict[str, int]) -> str:
    """Truncate to widths[key] (or unlimited if widths[key] >= FULL_WIDTH).

    Whitespace-collapses newlines so a multi-paragraph body still fits on
    one terminal line, and trims multiple spaces so the output stays
    grep-able.
    """
    s = str(value) if value is not None else ""
    s = s.replace("\n", " ").replace("\r", " ")
    s = " ".join(s.split())  # collapse runs of whitespace
    w = widths.get(key, DEFAULT_FIELD_WIDTHS.get(key, 120))
    if w >= FULL_WIDTH or len(s) <= w:
        return s
    return s[:w] + f"…(+{len(s) - w})"


FULL_FIELD_WIDTHS = {k: FULL_WIDTH for k in DEFAULT_FIELD_WIDTHS}


def _format_event(ev: dict, *, human: bool = False, full: bool = False) -> str:
    """Render one comms event as a single dense line.

    Format: ``[HH:MM:SS.mmm] LABEL  key=value key=value``

    By default each field is truncated to ``DEFAULT_FIELD_WIDTHS`` so the
    line stays one terminal row. Pass ``full=True`` to emit the entire
    value (good for piping to jq / grep, or for piping into a pager).
    The comms stream itself is untruncated — this is a display concern.

    With ``--human``, the label is colored (severity-coded) and a
    bullet precedes the time. Without it, the line is plain ASCII so an
    AI agent can grep / parse it without ANSI strippers.
    """
    et = ev.get("type", "?")
    data = ev.get("data") or {}
    ts = _ts_to_hms(ev.get("ts", ""))
    label, extractor = RENDERERS.get(et, (UNKNOWN_LABEL, lambda _d: []))
    try:
        kv = extractor(data)
    except Exception:
        kv = []
    widths = FULL_FIELD_WIDTHS if full else DEFAULT_FIELD_WIDTHS
    parts = "  ".join(f"{k}={_cap(v, k, widths)}" for k, v in kv)
    line = f"[{ts}] {label:<14} {parts}".rstrip()
    if not human:
        return line
    # Human mode: severity-aware coloring on FINDING/SCAN events.
    from rich.console import Console
    from rich.text import Text
    txt = Text()
    txt.append(f"[{ts}] ", style="dim")
    sev_color = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }.get(str(data.get("severity", "")).lower(), "cyan")
    label_color = sev_color if "FINDING" in label or "SCAN_COMPLETE" in label else "cyan"
    if label == "UNFILED":
        # Highlight the missing-finding warning so it stands out from
        # ordinary chatter. Magenta background, white text.
        label_color = "bold white on magenta"
    txt.append(f"{label:<14} ", style=label_color)
    if parts:
        txt.append(parts)
    return txt


def list_runs() -> list[dict]:
    """List all known runs in COMMS_ROOT with summary stats.

    Sorted by last event time, newest first.
    """
    if not COMMS_ROOT.exists():
        return []
    out = []
    for run_dir in sorted(COMMS_ROOT.iterdir()):
        if not run_dir.is_dir():
            continue
        status_path = run_dir / "status.jsonl"
        findings_path = run_dir / "findings.json"
        info: dict[str, Any] = {"run_id": run_dir.name}
        # First + last event
        first_ts = last_ts = None
        event_count = 0
        type_counts: dict[str, int] = {}
        if status_path.exists():
            try:
                with status_path.open() as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        event_count += 1
                        t = ev.get("type", "?")
                        type_counts[t] = type_counts.get(t, 0) + 1
                        ts = ev.get("ts", "")
                        if first_ts is None:
                            first_ts = ts
                        last_ts = ts
            except OSError:
                pass
        # Findings
        findings = []
        if findings_path.exists():
            try:
                findings = json.loads(findings_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        info["events"] = event_count
        info["first_event"] = first_ts
        info["last_event"] = last_ts
        info["findings_count"] = len(findings) if isinstance(findings, list) else 0
        info["type_counts"] = type_counts
        info["active"] = (
            type_counts.get("scan_complete", 0) == 0
            and type_counts.get("scan_start", 0) > 0
        )
        out.append(info)
    out.sort(key=lambda r: r.get("last_event") or "", reverse=True)
    return out


def resolve_run_id(arg: str | None) -> str | None:
    """Resolve a run_id from arg: explicit value, latest active, or latest overall."""
    if arg:
        return arg
    runs = list_runs()
    if not runs:
        return None
    active = [r for r in runs if r.get("active")]
    if active:
        return active[0]["run_id"]
    return runs[0]["run_id"]


def iter_events(run_id: str) -> Iterator[dict]:
    """Yield parsed events from a run's status.jsonl, oldest first."""
    p = COMMS_ROOT / run_id / "status.jsonl"
    if not p.exists():
        return
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def follow_events(run_id: str, offset: int) -> Iterator[dict]:
    """Tail status.jsonl, yielding new events as they arrive.

    Uses an inotify-style poll (Python's stdlib doesn't ship inotify on
    Linux for non-__linux__-specific bindings). 50ms poll is cheap; events
    are batched if multiple arrive between polls.
    """
    p = COMMS_ROOT / run_id / "status.jsonl"
    if not p.exists():
        # Wait for it to appear (scan just starting)
        for _ in range(100):  # 10s
            if p.exists():
                break
            time.sleep(0.1)
        else:
            return
    # Skip to offset
    skipped = 0
    with p.open() as f:
        for _ in iter_events(run_id):
            skipped += 1
            if skipped >= offset:
                break
            f.readline()  # advance the file handle
    with p.open() as f:
        # Catch up to EOF
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
        # Then poll
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                # No new data — sleep then retry
                time.sleep(0.5)
                # Detect truncation/rotation
                try:
                    cur_size = p.stat().st_size
                    if cur_size < pos:
                        # File was truncated/rotated; reopen
                        f.close()
                        f = p.open()
                        continue
                except OSError:
                    return
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def cmd_list(args: argparse.Namespace) -> int:
    runs = list_runs()
    if not runs:
        print("(no runs found in", COMMS_ROOT, ")")
        return 0
    # Print as a table; AI-friendly (no decoration)
    print(f"{'RUN_ID':<35} {'EVENTS':>7} {'FIND':>5}  {'FIRST':<20} {'LAST':<20} ACT")
    for r in runs:
        print(
            f"{r['run_id']:<35} "
            f"{r['events']:>7} "
            f"{r['findings_count']:>5}  "
            f"{(r['first_event'] or '-')[:19]:<20} "
            f"{(r['last_event'] or '-')[:19]:<20} "
            f"{'YES' if r['active'] else '-'}".rstrip()
        )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    run_id = resolve_run_id(args.run_id)
    if not run_id:
        print("(no runs found)", file=sys.stderr)
        return 1
    print(f"=== {run_id} ===")
    runs_info = {r["run_id"]: r for r in list_runs()}
    info = runs_info.get(run_id, {})
    if info:
        print(
            f"events={info.get('events', 0)} "
            f"findings={info.get('findings_count', 0)} "
            f"active={'yes' if info.get('active') else 'no'} "
            f"first={info.get('first_event', '-')} "
            f"last={info.get('last_event', '-')}"
        )
    print("---")
    events = list(iter_events(run_id))
    # Filter and slice
    if args.filter:
        events = [e for e in events if _matches_filter(e, args.filter)]
    if args.since:
        events = [e for e in events if e.get("ts", "") >= args.since]
    if args.last:
        events = events[-args.last:]
    elif not args.since:
        events = events[-30:]
    if not events:
        print("(no matching events)")
        return 0
    for ev in events:
        if args.human:
            from rich.console import Console
            Console().print(_format_event(ev, human=True, full=getattr(args, "full", False)))
        else:
            print(_format_event(ev, full=getattr(args, "full", False)))
    return 0


def cmd_follow(args: argparse.Namespace) -> int:
    run_id = resolve_run_id(args.run_id)
    if not run_id:
        print("(no runs found; waiting...)", file=sys.stderr)
        # Wait up to 30s for a run to appear
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(1)
            run_id = resolve_run_id(None)
            if run_id:
                break
        if not run_id:
            print("(timed out waiting for a run)", file=sys.stderr)
            return 1
    print(f"# following {run_id} (Ctrl+C to stop)", file=sys.stderr)
    if args.human:
        from rich.console import Console
        con = Console()
    seen_scan_complete = False
    try:
        for ev in follow_events(run_id, args.offset):
            if args.filter and not _matches_filter(ev, args.filter):
                continue
            if args.since and ev.get("ts", "") < args.since:
                continue
            line = _format_event(ev, human=args.human, full=getattr(args, "full", False))
            if args.human:
                con.print(line)
            else:
                print(line)
            sys.stdout.flush() if not args.human else None
            if ev.get("type") in ("scan_complete", "scan_completed"):
                seen_scan_complete = True
                # Keep going for a few more seconds in case trailing events
                # (tool_output etc.) arrive, then exit.
                if not args.keep_alive:
                    time.sleep(2)
                    break
    except KeyboardInterrupt:
        pass
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    run_id = resolve_run_id(args.run_id)
    if not run_id:
        print("(no runs found)", file=sys.stderr)
        return 1
    p = COMMS_ROOT / run_id / "status.jsonl"
    if not p.exists():
        return 0
    with p.open() as f:
        if args.follow:
            # Tail mode: print existing, then follow.
            data = f.read()
            sys.stdout.write(data)
            sys.stdout.flush()
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        continue
                    sys.stdout.write(line)
                    sys.stdout.flush()
            except KeyboardInterrupt:
                pass
        else:
            sys.stdout.write(f.read())
    return 0


def _matches_filter(ev: dict, flt: str) -> bool:
    """Match an event against a filter spec.

    Filter syntax (simple, AI-readable):
      TYPE                  exact event type match (e.g. "finding")
      TYPE:KEY=VAL          type + data field match (e.g. "finding:severity=high")
      KEY=VAL               any event with data.key==val
    """
    et = ev.get("type", "")
    data = ev.get("data") or {}
    if ":" in flt:
        type_part, kv_part = flt.split(":", 1)
        if et != type_part:
            return False
        flt = kv_part
    elif "=" not in flt:
        return et == flt
    if "=" in flt:
        k, v = flt.split("=", 1)
        return str(data.get(k, "")) == v
    return True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Real-time visibility into prometheus scans.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--comms-root",
        type=Path,
        default=COMMS_ROOT,
        help=f"Override comms directory (default: {COMMS_ROOT})",
    )
    sub = p.add_subparsers(dest="cmd", required=False)

    p_list = sub.add_parser("list", help="List all runs")
    p_list.set_defaults(func=cmd_list)

    p_status = sub.add_parser("status", help="One-shot dump of recent events")
    p_status.add_argument("run_id", nargs="?", help="Run ID (default: latest)")
    p_status.add_argument("--filter", "-f", help="Filter spec (e.g. 'finding')")
    p_status.add_argument("--since", help="Only events with ts >= this ISO 8601 string")
    p_status.add_argument("--last", type=int, help="Only the last N events (default 30)")
    p_status.add_argument("--human", action="store_true", help="Pretty colored output")
    p_status.add_argument(
        "--full", action="store_true",
        help="Don't truncate field values. The comms stream is the record; "
             "this just removes the per-line cap so jq / grep / pager see the full body.",
    )
    p_status.set_defaults(func=cmd_status)

    p_follow = sub.add_parser("follow", help="Stream events as they happen (default)")
    p_follow.add_argument("run_id", nargs="?", help="Run ID (default: latest active)")
    p_follow.add_argument("--filter", "-f", help="Filter spec")
    p_follow.add_argument("--since", help="Only events with ts >= this ISO 8601 string")
    p_follow.add_argument("--offset", type=int, default=0, help="Skip first N events")
    p_follow.add_argument("--human", action="store_true", help="Pretty colored output")
    p_follow.add_argument(
        "--full", action="store_true",
        help="Don't truncate field values when rendering.",
    )
    p_follow.add_argument(
        "--keep-alive",
        action="store_true",
        help="Don't exit after scan_complete (default: exit 2s after)",
    )
    p_follow.set_defaults(func=cmd_follow)

    p_events = sub.add_parser("events", help="Raw JSONL dump (NDJSON)")
    p_events.add_argument("run_id", nargs="?", help="Run ID (default: latest)")
    p_events.add_argument("--follow", "-f", action="store_true", help="Tail mode")
    p_events.set_defaults(func=cmd_events)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        # Default: follow
        args.run_id = None
        args.func = cmd_follow
        args.filter = getattr(args, "filter", None)
        args.since = getattr(args, "since", None)
        args.offset = getattr(args, "offset", 0)
        args.human = getattr(args, "human", False)
        args.keep_alive = getattr(args, "keep_alive", False)
    # Allow COMMS_ROOT override via env or flag
    global COMMS_ROOT
    if args.comms_root:
        COMMS_ROOT = args.comms_root
    # SIGPIPE -> exit cleanly when piping through head
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError):
        pass
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
