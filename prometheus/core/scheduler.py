"""Background scan scheduler for prometheus.

Periodically re-scans targets based on their scan history:
- Targets with accepted findings: 12 hours (active exploitation window)
- Targets where last 3 scans found nothing: 72 hours (low priority)
- Never-scanned targets: 0 (immediate)
- Default: 24 hours

Thread-safe singleton pattern — one ``ScanScheduler`` per process.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Self


logger = logging.getLogger(__name__)

_DEFAULT_CHECK_INTERVAL = 600  # 10 minutes
_DEFAULT_INTERVAL_HOURS = 24
_VULN_INTERVAL_HOURS = 12
_SLOW_INTERVAL_HOURS = 72  # 3 days — targets with 3+ empty scans

_instance: ScanScheduler | None = None
_instance_lock = threading.Lock()


class ScanScheduler:
    """Background daemon that launches scheduled re-scans.

    Use ``ScanScheduler()`` — the singleton pattern guarantees one
    scheduler per process.
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

    def __init__(
        self,
        *,
        check_interval: int = _DEFAULT_CHECK_INTERVAL,
    ) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self._check_interval = check_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        # Track which targets have had vulns (shorter re-scan)
        self._targets_with_vulns: set[str] = set()
        # Per-target overrides: target_id -> interval_hours
        self._schedule_overrides: dict[str, int] = {}
        # Paused targets
        self._paused_targets: set[str] = set()
        logger.info(
            "ScanScheduler initialised (check_interval=%ds)",
            self._check_interval,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Whether the scheduler daemon thread is alive."""
        return self._running and self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """DISABLED — automatic scheduled scans are not used.

        Prometheus runs point-in-time scans only. The scheduler class is kept
        for reference and manual schedule queries via the agent tools.
        """
        logger.info("ScanScheduler is disabled — automatic scans are not enabled")
        self._running = False
        return

    def stop(self, *, timeout: float = 15.0) -> None:
        """Gracefully stop the scheduler daemon."""
        if not self.is_running:
            logger.info("ScanScheduler not running")
            return
        logger.info("ScanScheduler stopping...")
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("ScanScheduler thread did not stop within %ss", timeout)
            self._thread = None
        logger.info("ScanScheduler stopped")

    def set_schedule(self, target_id: str, interval_hours: int) -> None:
        """Override the scan interval for a specific target."""
        with self._lock:
            self._schedule_overrides[target_id] = max(1, interval_hours)
        logger.info(
            "Schedule override: target=%s interval=%dh",
            target_id,
            interval_hours,
        )

    def pause_schedule(self, target_id: str) -> None:
        """Pause scheduled scanning for a target."""
        with self._lock:
            self._paused_targets.add(target_id)
        logger.info("Schedule paused for target=%s", target_id)

    def resume_schedule(self, target_id: str) -> None:
        """Resume scheduled scanning for a target."""
        with self._lock:
            self._paused_targets.discard(target_id)
        logger.info("Schedule resumed for target=%s", target_id)

    def mark_target_had_vulns(self, target_id: str) -> None:
        """Mark that a target previously found vulnerabilities.

        This triggers shorter re-scan intervals for that target.
        """
        with self._lock:
            self._targets_with_vulns.add(target_id)
        logger.info("Target=%s marked as having vulns (shorter interval)", target_id)

    def get_due_scans(self) -> list[dict[str, Any]]:
        """Return targets that are currently due for a re-scan."""
        from prometheus.core.target_registry import TargetRegistry

        registry = TargetRegistry()
        now = datetime.now(UTC)
        due: list[dict[str, Any]] = []

        with self._lock:
            paused = set(self._paused_targets)

        try:
            targets = registry.list_targets(status="active")
        except Exception:
            logger.exception("Failed to list targets")
            return due

        for target in targets:
            tid = target["id"]
            if tid in paused:
                continue
            schedule = target.get("schedule") or {}
            next_scan_str = schedule.get("next_scan_at")
            if next_scan_str is None:
                # Never scanned — schedule immediately
                due.append(target)
                continue
            try:
                next_scan = datetime.fromisoformat(next_scan_str)
                if next_scan.tzinfo is None:
                    next_scan = next_scan.replace(tzinfo=UTC)
            except (ValueError, TypeError):
                logger.warning("Invalid next_scan_at for target=%s: %s", tid, next_scan_str)
                due.append(target)
                continue
            if next_scan <= now:
                due.append(target)

        return due

    def get_schedule_info(self) -> list[dict[str, Any]]:
        """Return schedule info for all active targets."""
        from prometheus.core.target_registry import TargetRegistry

        registry = TargetRegistry()
        with self._lock:
            paused = set(self._paused_targets)
            vulns = set(self._targets_with_vulns)
            overrides = dict(self._schedule_overrides)

        try:
            targets = registry.list_targets(status="active")
        except Exception:
            logger.exception("Failed to list targets")
            return []

        result: list[dict[str, Any]] = []
        for target in targets:
            tid = target["id"]
            schedule = target.get("schedule") or {}
            interval = overrides.get(tid, schedule.get("interval_hours", _DEFAULT_INTERVAL_HOURS))
            if tid in vulns and tid not in overrides:
                interval = _VULN_INTERVAL_HOURS
            result.append(
                {
                    "target_id": tid,
                    "domain": target.get("domain", ""),
                    "interval_hours": interval,
                    "next_scan_at": schedule.get("next_scan_at"),
                    "last_scan_id": schedule.get("last_scan_id"),
                    "paused": tid in paused,
                    "had_vulns": tid in vulns,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Smart interval calculation
    # ------------------------------------------------------------------

    def _calculate_next_interval(self, target_id: str) -> int:
        """Determine the next scan interval (hours) based on scan history.

        Rules:
        - If target has accepted findings: 12 hours (tight monitoring)
        - If last 3 scans found nothing: 72 hours (low priority)
        - If never scanned: 0 (immediate first scan)
        - Default: 24 hours
        """
        from prometheus.core.scan_persistence import ScanPersistence

        # Manual override always wins
        with self._lock:
            if target_id in self._schedule_overrides:
                return self._schedule_overrides[target_id]

        # Check if target is known to have had vulns (short interval)
        with self._lock:
            if target_id in self._targets_with_vulns:
                return _VULN_INTERVAL_HOURS

        # Query scan history from persistence
        try:
            persistence = ScanPersistence()
            with persistence._lock:
                rows = persistence._conn.execute(
                    """
                    SELECT findings_count, status, started_at
                    FROM scans
                    WHERE target_id = ?
                    ORDER BY started_at DESC
                    LIMIT 3
                    """,
                    (target_id,),
                ).fetchall()
        except Exception:
            logger.debug(
                "Could not query scan history for target=%s, using default interval",
                target_id,
                exc_info=True,
            )
            return _DEFAULT_INTERVAL_HOURS

        # Never scanned — immediate
        if not rows:
            logger.info(
                "Target=%s never scanned, scheduling immediately",
                target_id,
            )
            return 0

        # Check if last 3 scans found nothing → slow interval
        if len(rows) >= 3:
            all_empty = all(
                (row["findings_count"] or 0) == 0 and row["status"] == "completed" for row in rows
            )
            if all_empty:
                logger.info(
                    "Target=%s: last 3 scans clean, using %dh interval",
                    target_id,
                    _SLOW_INTERVAL_HOURS,
                )
                return _SLOW_INTERVAL_HOURS

        # Check if any recent scan had findings (medium-high)
        has_findings = any((row["findings_count"] or 0) > 0 for row in rows)
        if has_findings:
            logger.info(
                "Target=%s: recent scan had findings, using %dh interval",
                target_id,
                _VULN_INTERVAL_HOURS,
            )
            return _VULN_INTERVAL_HOURS

        # Default
        return _DEFAULT_INTERVAL_HOURS

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Main scheduler loop — runs until stop() is called."""
        logger.info("ScanScheduler loop running")
        while self._running:
            try:
                self._tick()
            except Exception:
                logger.exception("ScanScheduler tick failed")
            # Wait for the check interval or until stop is signalled
            if self._stop_event.wait(timeout=self._check_interval):
                break
        logger.info("ScanScheduler loop exited")

    def _tick(self) -> None:
        """Single scheduler tick — check due scans and launch if capacity allows."""
        from prometheus.core.orchestrator import ScanOrchestrator
        from prometheus.core.target_registry import TargetRegistry

        due = self.get_due_scans()
        if not due:
            logger.debug("No due scans")
            return

        logger.info("Found %d due scan(s)", len(due))
        orchestrator = ScanOrchestrator()
        registry = TargetRegistry()

        with self._lock:
            paused = set(self._paused_targets)

        for target in due:
            if not self._running:
                break

            tid = target["id"]
            if tid in paused:
                continue

            # Check capacity
            active_count, max_concurrent = orchestrator.get_capacity()
            if active_count >= max_concurrent:
                logger.info(
                    "Orchestrator at capacity (%d/%d), deferring remaining targets",
                    active_count,
                    max_concurrent,
                )
                break

            # Don't launch if target already has an active scan
            if orchestrator.get_scan_for_target(tid) is not None:
                logger.debug("Target=%s already has active scan, skipping", tid)
                continue

            # Determine interval for next reschedule using smart calculation
            interval = self._calculate_next_interval(tid)

            domain = target.get("domain", tid)
            logger.info("Launching scheduled scan for target=%s domain=%s", tid, domain)

            try:
                scan_id = orchestrator.launch_scan(tid)
                logger.info("Launched scan=%s for target=%s", scan_id, tid)

                # Register a callback to update the schedule after scan completes
                self._register_completion_hook(orchestrator, scan_id, tid, interval, registry)

                # Update next_scan_at immediately so we don't re-launch
                next_scan = datetime.now(UTC) + timedelta(hours=interval)
                registry.update_target(tid)  # touch updated_at
                self._update_schedule_fields(registry, tid, next_scan, scan_id=None)

            except RuntimeError as exc:
                logger.warning("Could not launch scan for target=%s: %s", tid, exc)
            except Exception:
                logger.exception("Unexpected error launching scan for target=%s", tid)

    def _register_completion_hook(
        self,
        orchestrator: Any,
        scan_id: str,
        target_id: str,
        interval_hours: int,
        registry: Any,
    ) -> None:
        """Poll until the scan finishes, then update the schedule."""

        def _watcher() -> None:
            try:
                while self._running:
                    instance = orchestrator.get_scan(scan_id)
                    if instance is None or instance.status in {"completed", "failed", "stopped"}:
                        break
                    time.sleep(10)
                # Scan finished — re-calculate smart interval based on results
                smart_interval = self._calculate_next_interval(target_id)
                next_scan = datetime.now(UTC) + timedelta(hours=smart_interval)
                self._update_schedule_fields(registry, target_id, next_scan, scan_id)
                logger.info(
                    "Updated schedule for target=%s: next_scan=%s last_scan=%s",
                    target_id,
                    next_scan.isoformat(),
                    scan_id,
                )
            except Exception:
                logger.exception("Completion watcher failed for scan=%s", scan_id)

        t = threading.Thread(
            target=_watcher,
            name=f"prometheus-sched-watcher-{scan_id}",
            daemon=True,
        )
        t.start()

    @staticmethod
    def _update_schedule_fields(
        registry: Any,
        target_id: str,
        next_scan: datetime,
        scan_id: str | None,
    ) -> None:
        """Update schedule.next_scan_at and schedule.last_scan_id in the registry."""
        import json

        with registry._lock:
            row = registry._conn.execute(
                "SELECT schedule FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            if row is None:
                return
            schedule = (
                json.loads(row["schedule"])
                if isinstance(row["schedule"], str)
                else dict(row["schedule"])
            )
            schedule["next_scan_at"] = next_scan.isoformat()
            if scan_id is not None:
                schedule["last_scan_id"] = scan_id
            registry._conn.execute(
                "UPDATE targets SET schedule = ?, updated_at = ? WHERE id = ?",
                (
                    json.dumps(schedule, ensure_ascii=False),
                    datetime.now(UTC).isoformat(),
                    target_id,
                ),
            )
            registry._conn.commit()

    # ------------------------------------------------------------------
    # Reset (for testing)
    # ------------------------------------------------------------------

    @classmethod
    def _reset_singleton(cls) -> None:
        """Reset the singleton instance (for testing only)."""
        global _instance  # noqa: PLW0603
        if _instance is not None:
            _instance.stop()
        with _instance_lock:
            _instance = None


def get_scheduler() -> ScanScheduler:
    """Convenience accessor for the singleton."""
    return ScanScheduler()
