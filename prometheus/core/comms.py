"""Two-way communication channel between prometheus and the Hermes agent.

prometheus writes status updates, findings, and questions to a JSONL file.
The Hermes agent reads this file and can send instructions back via another file.

File layout (created per run):
  ~/.prometheus/comms/<run_id>/status.jsonl   — prometheus writes, Hermes reads
  ~/.prometheus/comms/<run_id>/control.jsonl  — Hermes writes, prometheus reads
  ~/.prometheus/comms/<run_id>/findings.json  — accumulated findings
"""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


_COMMS_ROOT = Path.home() / ".prometheus" / "comms"
_active_run_id: str | None = None


def set_active_run(run_id: str) -> None:
    """Set the active run ID for automatic status reporting."""
    global _active_run_id
    _active_run_id = run_id
    init_comms(run_id)


def get_active_run() -> str | None:
    return _active_run_id


def _ensure_dir(run_id: str) -> Path:
    d = _COMMS_ROOT / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def init_comms(run_id: str) -> Path:
    """Initialize the comms directory for a run. Returns the directory path."""
    d = _ensure_dir(run_id)
    # Create files if they don't exist
    (d / "status.jsonl").touch(exist_ok=True)
    (d / "control.jsonl").touch(exist_ok=True)
    if not (d / "findings.json").exists():
        (d / "findings.json").write_text("[]")
    return d


def write_status(run_id: str, event_type: str, data: dict[str, Any]) -> None:
    """Write a status event for the Hermes agent to read."""
    d = _ensure_dir(run_id)
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "type": event_type,
        "data": data,
    }
    with open(d / "status.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def write_finding(run_id: str, finding: dict[str, Any]) -> None:
    """Append a finding to the findings file."""
    d = _ensure_dir(run_id)
    path = d / "findings.json"
    try:
        findings = json.loads(path.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        logger.debug("write_finding: could not read findings file; starting fresh", exc_info=True)
        findings = []
    finding["ts"] = datetime.now(UTC).isoformat()
    findings.append(finding)
    path.write_text(json.dumps(findings, indent=2))
    # Also write to status log
    write_status(run_id, "finding", finding)


def ask_question(run_id: str, question: str, context: str = "") -> None:
    """Ask the Hermes agent a question (e.g., 'should I pivot to testing X?')."""
    write_status(run_id, "question", {"question": question, "context": context})


def read_control(run_id: str, since_line: int = 0) -> list[dict[str, Any]]:
    """Read control messages from the Hermes agent. Returns new messages since last read."""
    d = _ensure_dir(run_id)
    path = d / "control.jsonl"
    if not path.exists():
        return []
    messages = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i >= since_line and line.strip():
                with contextlib.suppress(json.JSONDecodeError):
                    messages.append(json.loads(line))
    return messages


def send_instruction(run_id: str, instruction: str, action: str = "instruct") -> None:
    """Hermes agent sends an instruction to prometheus."""
    d = _ensure_dir(run_id)
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "action": action,
        "instruction": instruction,
    }
    with open(d / "control.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")
    # Also log to status
    write_status(run_id, "instruction_received", entry)


def get_status_summary(run_id: str) -> dict[str, Any]:
    """Get a summary of the current run status."""
    d = _ensure_dir(run_id)
    status_path = d / "status.jsonl"
    findings_path = d / "findings.json"

    # Read last 10 status events
    recent_events = []
    if status_path.exists():
        with open(status_path) as f:
            lines = f.readlines()
            for line in lines[-10:]:
                with contextlib.suppress(json.JSONDecodeError):
                    recent_events.append(json.loads(line))

    # Read findings
    findings = []
    if findings_path.exists():
        with contextlib.suppress(json.JSONDecodeError, FileNotFoundError):
            findings = json.loads(findings_path.read_text())

    # Read unread control messages
    control_path = d / "control.jsonl"
    control_count = 0
    if control_path.exists():
        with open(control_path) as f:
            control_count = sum(1 for line in f if line.strip())

    return {
        "run_id": run_id,
        "recent_events": recent_events,
        "findings_count": len(findings),
        "findings": findings,
        "instructions_sent": control_count,
    }


def list_active_runs() -> list[str]:
    """List all active comms directories."""
    if not _COMMS_ROOT.exists():
        return []
    return [d.name for d in _COMMS_ROOT.iterdir() if d.is_dir()]


def cleanup_comms(run_id: str) -> None:
    """Clean up comms directory for a completed run."""
    import shutil

    d = _COMMS_ROOT / run_id
    if d.exists():
        shutil.rmtree(d)
