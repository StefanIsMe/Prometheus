"""Notifications for prometheus scan events and findings.

Writes scan events to ~/.prometheus/comms/global/status.jsonl
and findings to ~/.prometheus/comms/global/findings.json.

Thread-safe singleton pattern — one ``ScanNotifications`` per process.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self


logger = logging.getLogger(__name__)

_COMMS_GLOBAL = Path.home() / ".prometheus" / "comms" / "global"

_instance: ScanNotifications | None = None
_instance_lock = threading.Lock()


class ScanNotifications:
    """Singleton that listens for scan events and writes them to comms files.

    Use ``ScanNotifications()`` — the singleton pattern guarantees one
    instance per process.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            _instance = inst
            return inst

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self._lock = threading.Lock()
        self._running = False
        self._orchestrator_ref: Any = None
        _COMMS_GLOBAL.mkdir(parents=True, exist_ok=True)
        logger.info("ScanNotifications initialised (%s)", _COMMS_GLOBAL)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, orchestrator: Any = None) -> None:
        """Start listening for scan events.

        If *orchestrator* is provided, registers ``on_scan_event`` on it.
        """
        self._running = True
        if orchestrator is not None:
            self._orchestrator_ref = orchestrator
            orchestrator.on_scan_event = self._handle_scan_event
            logger.info("ScanNotifications registered on orchestrator")

    def stop(self) -> None:
        """Stop listening for scan events."""
        self._running = False
        if self._orchestrator_ref is not None:
            self._orchestrator_ref.on_scan_event = None
            self._orchestrator_ref = None
        logger.info("ScanNotifications stopped")

    def notify_finding(self, finding_data: dict[str, Any]) -> None:
        """Write a finding to the global findings file and status log."""
        finding_data = dict(finding_data)  # defensive copy
        finding_data.setdefault("ts", datetime.now(UTC).isoformat())

        with self._lock:
            self._write_finding(finding_data)
            self._write_status("finding", finding_data)

        logger.info(
            "Notified finding: id=%s severity=%s",
            finding_data.get("id", "unknown"),
            finding_data.get("severity", "unknown"),
        )

    def notify_scan_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Write a scan event to the global status log."""
        data = dict(data)
        data.setdefault("event_type", event_type)
        with self._lock:
            self._write_status(event_type, data)

        logger.debug("Notified scan event: %s", event_type)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handle_scan_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Callback registered on the orchestrator."""
        if not self._running:
            return
        self.notify_scan_event(event_type, data)

    def _write_status(self, event_type: str, data: dict[str, Any]) -> None:
        """Append an event to ~/.prometheus/comms/global/status.jsonl."""
        path = _COMMS_GLOBAL / "status.jsonl"
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "type": event_type,
            "data": data,
        }
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            logger.exception("Failed to write status event")

    def _write_finding(self, finding: dict[str, Any]) -> None:
        """Append a finding to ~/.prometheus/comms/global/findings.json."""
        path = _COMMS_GLOBAL / "findings.json"
        try:
            findings = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        except (json.JSONDecodeError, OSError):
            logger.debug(
                "_write_finding: could not read findings file; starting fresh", exc_info=True
            )
            findings = []

        findings.append(finding)

        try:
            path.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        except OSError:
            logger.exception("Failed to write findings file")


def get_notifications() -> ScanNotifications:
    """Convenience accessor for the singleton."""
    return ScanNotifications()
