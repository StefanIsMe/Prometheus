#!/usr/bin/env python3
"""Watch a prometheus scan and report status to stdout. Use from Hermes to monitor scans."""

import json
import logging
import sys
import time
from pathlib import Path

COMMS_ROOT = Path.home() / ".prometheus" / "comms"

logger = logging.getLogger(__name__)


def watch(run_id: str, poll_interval: float = 5.0):
    """Watch a prometheus scan and print status updates to stdout."""
    status_path = COMMS_ROOT / run_id / "status.jsonl"
    findings_path = COMMS_ROOT / run_id / "findings.json"

    if not status_path.exists():
        print(f"ERROR: No comms directory for run {run_id}")
        print(
            f"Active runs: {[d.name for d in COMMS_ROOT.iterdir()] if COMMS_ROOT.exists() else 'none'}"
        )
        sys.exit(1)

    last_line = 0
    last_finding_count = 0

    print(f"Watching prometheus scan: {run_id}")
    print(f"Status: {status_path}")
    print(f"Findings: {findings_path}")
    print("---")

    while True:
        # Read new status events
        try:
            with open(status_path) as f:
                lines = f.readlines()
        except FileNotFoundError:
            break

        new_lines = lines[last_line:]
        for line in new_lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                ts = event.get("ts", "?")[:19]
                etype = event.get("type", "?")
                data = event.get("data", {})

                if etype == "tool_call":
                    cmd = data.get("command", "")[:80]
                    print(f"[{ts}] TOOL: {cmd}")
                elif etype == "turn_start":
                    print(f"[{ts}] TURN {data.get('turn', '?')}")
                elif etype == "finding":
                    title = data.get("title", data.get("description", "unknown"))
                    sev = data.get("severity", "?")
                    print(f"[{ts}] FINDING [{sev}]: {title}")
                elif etype == "question":
                    print(f"[{ts}] QUESTION: {data.get('question', '')}")
                elif etype == "scan_start":
                    print(f"[{ts}] SCAN STARTED: {data.get('targets', [])}")
                elif etype == "scan_complete":
                    print(f"[{ts}] SCAN COMPLETE")
                    return
                elif etype == "instruction_received":
                    print(f"[{ts}] INSTRUCTION: {data.get('instruction', '')[:80]}")
                else:
                    print(f"[{ts}] {etype}: {json.dumps(data)[:100]}")
            except json.JSONDecodeError:
                logger.debug("status line %d not valid JSON, skipping", len(lines), exc_info=True)
        last_line = len(lines)

        # Check for new findings
        try:
            findings = json.loads(findings_path.read_text())
            if len(findings) > last_finding_count:
                new_findings = findings[last_finding_count:]
                for f in new_findings:
                    print(
                        f"  *** NEW FINDING: {f.get('title', f.get('description', 'unknown'))} ***"
                    )
                last_finding_count = len(findings)
        except (json.JSONDecodeError, FileNotFoundError):
            logger.debug("findings.json unreadable, skipping", exc_info=True)

        time.sleep(poll_interval)


def send(run_id: str, instruction: str, action: str = "instruct"):
    """Send an instruction to a running prometheus scan."""
    ctrl_path = COMMS_ROOT / run_id / "control.jsonl"
    if not ctrl_path.exists():
        print(f"ERROR: No comms directory for run {run_id}")
        sys.exit(1)

    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "instruction": instruction,
    }
    with open(ctrl_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"Sent to {run_id}: {instruction}")


def status(run_id: str):
    """Print current status of a prometheus scan."""
    status_path = COMMS_ROOT / run_id / "status.jsonl"
    findings_path = COMMS_ROOT / run_id / "findings.json"

    if not status_path.exists():
        print(f"ERROR: No comms directory for run {run_id}")
        sys.exit(1)

    # Count events
    with open(status_path) as f:
        lines = f.readlines()

    event_counts = {}
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            etype = event.get("type", "?")
            event_counts[etype] = event_counts.get(etype, 0) + 1
        except json.JSONDecodeError:
            logger.debug("event line not valid JSON, skipping", exc_info=True)

    # Count findings
    findings = []
    try:
        findings = json.loads(findings_path.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        logger.debug("findings.json unreadable, treating as empty", exc_info=True)

    print(f"Scan: {run_id}")
    print(f"Events: {len(lines)} total")
    for etype, count in sorted(event_counts.items()):
        print(f"  {etype}: {count}")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - [{f.get('severity', '?')}] {f.get('title', f.get('description', 'unknown'))}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  prometheus_comms.py watch <run_id> [poll_interval]")
        print("  prometheus_comms.py send <run_id> <instruction>")
        print("  prometheus_comms.py status <run_id>")
        sys.exit(1)

    cmd = sys.argv[1]
    run_id = sys.argv[2]

    if cmd == "watch":
        interval = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
        watch(run_id, interval)
    elif cmd == "send":
        instruction = sys.argv[3] if len(sys.argv) > 3 else ""
        send(run_id, instruction)
    elif cmd == "status":
        status(run_id)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
