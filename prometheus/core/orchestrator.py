"""Multi-scan orchestrator for prometheus.

Manages concurrent scan instances, each with its own agent coordinator,
live view, report state, and dedicated event-loop thread.

Thread-safe singleton pattern — one ``ScanOrchestrator`` per process.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Self

from prometheus.config import load_settings
from prometheus.core.agents import AgentCoordinator
from prometheus.core.runner import run_prometheus_scan
from prometheus.core.scan_persistence import ScanPersistence
from prometheus.core.target_registry import TargetRegistry
from prometheus.interface.tui.live_view import TuiLiveView
from prometheus.report.state import ReportState


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

ScanStatus = str  # "starting", "running", "completed", "failed", "stopped"

_instance: ScanOrchestrator | None = None
_instance_lock = threading.Lock()


@dataclass
class ScanInstance:
    """Holds all state for a single scan."""

    scan_id: str
    target_id: str
    target_name: str
    coordinator: AgentCoordinator
    live_view: TuiLiveView
    report_state: ReportState
    thread: threading.Thread | None = None
    loop: asyncio.AbstractEventLoop | None = None
    status: ScanStatus = "starting"
    started_at: str = ""
    scan_config: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    status_detail: str = ""  # Human-readable progress (e.g. "Creating sandbox...")


class ScanOrchestrator:
    """Manage multiple concurrent prometheus scans.

    Use ``ScanOrchestrator()`` — the singleton pattern guarantees one
    orchestrator per process.
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

    def __init__(self, *, max_concurrent: int | None = None) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        settings = load_settings()
        self._max_concurrent = max_concurrent or getattr(
            settings.runtime, "max_concurrent_scans", 2
        )
        self._scans: dict[str, ScanInstance] = {}
        self._lock = threading.Lock()
        self.on_scan_event: Callable[[str, dict[str, Any]], None] | None = None
        logger.info("ScanOrchestrator initialised (max_concurrent=%d)", self._max_concurrent)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @max_concurrent.setter
    def max_concurrent(self, value: int) -> None:
        self._max_concurrent = max(1, value)

    @property
    def scans(self) -> dict[str, ScanInstance]:
        """Read-only view of active scan instances."""
        with self._lock:
            return dict(self._scans)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def launch_scan(
        self,
        target_id: str,
        scan_config: dict[str, Any] | None = None,
    ) -> str:
        """Launch a new scan for *target_id* and return its *scan_id*.

        Raises ``RuntimeError`` if the orchestrator is at capacity.
        """
        with self._lock:
            active = sum(1 for s in self._scans.values() if s.status in {"starting", "running"})
            if active >= self._max_concurrent:
                raise RuntimeError(
                    f"At scan capacity ({active}/{self._max_concurrent}). "
                    f"Stop a running scan or increase max_concurrent_scans."
                )

        # Resolve target from registry if scan_config not fully provided
        registry = TargetRegistry()
        target = registry.get_target(target_id)
        if target is None:
            raise RuntimeError(f"Target '{target_id}' not found in registry")

        target_name: str = target.get("domain", target_id)
        stored_scan_config: dict[str, Any] = target.get("scan_config") or {}
        target_type: str = target.get("target_type", "url")

        # Merge caller-provided scan_config on top of stored config
        merged_config: dict[str, Any] = dict(stored_scan_config)
        if scan_config:
            merged_config.update(scan_config)

        # Build the scan_config dict that run_prometheus_scan expects
        final_config = self._build_run_config(
            target_id=target_id,
            target_name=target_name,
            target_type=target_type,
            target_record=target,
            scan_config=merged_config,
        )

        # Generate identifiers
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        domain_part = target_name.replace("/", "_").replace(":", "_")[:40]
        run_name = f"{domain_part}-{timestamp}"

        # Create per-scan objects
        report_state = ReportState(run_name=run_name)
        report_state.hydrate_from_run_dir()

        # Set global report state so create_vulnerability_report can persist findings
        from prometheus.report.state import set_global_report_state

        set_global_report_state(report_state)

        live_view = TuiLiveView()

        coordinator = AgentCoordinator()

        instance = ScanInstance(
            scan_id=scan_id,
            target_id=target_id,
            target_name=target_name,
            coordinator=coordinator,
            live_view=live_view,
            report_state=report_state,
            status="starting",
            started_at=datetime.now(UTC).isoformat(),
            scan_config=final_config,
        )

        with self._lock:
            self._scans[scan_id] = instance

        self._fire_event("scan_starting", instance)

        # Persist scan start
        ScanPersistence().record_scan_start(
            scan_id=scan_id,
            target_id=target_id,
            target_name=target_name,
            run_name=run_name,
            scan_config=final_config,
            run_dir=getattr(report_state, "run_dir", ""),
        )

        # Fetch the Docker image from settings
        settings = load_settings()
        image = settings.runtime.image

        # Event sink that feeds the live view
        _event_sink_errors = 0

        def event_sink(agent_id: str, event: Any) -> None:
            nonlocal _event_sink_errors
            try:
                live_view.ingest_sdk_event(agent_id, event)
                _event_sink_errors = 0  # Reset on success
            except Exception:  # noqa: BLE001
                _event_sink_errors += 1
                if _event_sink_errors <= 3:
                    logger.warning(
                        "event_sink error for %s (total: %d)",
                        agent_id,
                        _event_sink_errors,
                        exc_info=True,
                    )

        # Progress callback that feeds progress messages to the live view
        def progress_callback(msg: str) -> None:
            try:
                live_view.add_system_message(msg)
            except Exception:
                pass

        # Background thread: own event loop running run_prometheus_scan
        def _thread_target() -> None:
            loop = asyncio.new_event_loop()
            instance.loop = loop
            asyncio.set_event_loop(loop)
            instance.status = "running"
            self._fire_event("scan_running", instance)
            logger.debug("Scan %s thread started (event loop created)", scan_id)
            try:
                loop.run_until_complete(
                    run_prometheus_scan(
                        scan_config=final_config,
                        scan_id=scan_id,
                        image=image,
                        coordinator=coordinator,
                        event_sink=event_sink,
                        progress_callback=progress_callback,
                    )
                )
                instance.status = "completed"
                self._fire_event("scan_completed", instance)
                ScanPersistence().record_scan_end(
                    scan_id,
                    "completed",
                    findings_count=(
                        len(instance.report_state.vulnerability_reports)
                        if instance.report_state
                        else 0
                    ),
                )
            except Exception as exc:
                instance.status = "failed"
                instance.error = str(exc)
                logger.exception("Scan %s failed", scan_id)
                self._fire_event("scan_failed", instance)
                ScanPersistence().record_scan_end(
                    scan_id,
                    "failed",
                    findings_count=0,
                )
            finally:
                loop.close()
                instance.loop = None
                # Clear thread-local report state to avoid leaking to next scan
                try:
                    from prometheus.report.state import clear_thread_report_state

                    clear_thread_report_state()
                except Exception:
                    pass

        thread = threading.Thread(
            target=_thread_target,
            name=f"prometheus-scan-{scan_id}",
            daemon=False,
        )
        instance.thread = thread
        thread.start()

        logger.info(
            "Launched scan %s for target '%s' (target_id=%s)",
            scan_id,
            target_name,
            target_id,
        )
        return scan_id

    def stop_scan(self, scan_id: str) -> bool:
        """Request graceful stop of a scan.

        Returns ``True`` if the scan was found and a stop was requested.
        """
        with self._lock:
            instance = self._scans.get(scan_id)
        if instance is None:
            return False
        if instance.status not in {"starting", "running"}:
            return False

        instance.status = "stopped"
        self._fire_event("scan_stopping", instance)

        # Only attempt agent cancellation if the coordinator has agents
        stop_succeeded = True
        root_id = self._find_root_agent(instance.coordinator)
        if root_id is not None and instance.loop is not None:
            try:
                future = asyncio.run_coroutine_threadsafe(
                    instance.coordinator.request_stop(root_id),
                    instance.loop,
                )
                future.result(timeout=5)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "stop_scan(%s): request_stop failed, attempting cancel",
                    scan_id,
                    exc_info=True,
                )
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        instance.coordinator.cancel_descendants(root_id),
                        instance.loop,
                    )
                    future.result(timeout=3)
                except Exception:  # noqa: BLE001
                    stop_succeeded = False
                    logger.debug(
                        "stop_scan(%s): cancel also failed",
                        scan_id,
                        exc_info=True,
                    )

        if not stop_succeeded:
            instance.error = "Stop request failed — scan may still be running in background"
            logger.warning(
                "stop_scan(%s): stop partially failed, scan may still be active", scan_id
            )

        logger.info("Stop requested for scan %s", scan_id)
        return True

    def list_scans(self) -> list[dict[str, Any]]:
        """Return a summary list of all scan instances."""
        with self._lock:
            instances = list(self._scans.values())

        summaries: list[dict[str, Any]] = []
        for inst in instances:
            findings_count = (
                len(inst.report_state.vulnerability_reports) if inst.report_state else 0
            )
            summaries.append(
                {
                    "scan_id": inst.scan_id,
                    "target_id": inst.target_id,
                    "target_name": inst.target_name,
                    "status": inst.status,
                    "started_at": inst.started_at,
                    "findings_count": findings_count,
                    "error": inst.error,
                }
            )
        return summaries

    def get_scan(self, scan_id: str) -> ScanInstance | None:
        """Get a scan instance by its id."""
        with self._lock:
            return self._scans.get(scan_id)

    def get_scan_for_target(self, target_id: str) -> ScanInstance | None:
        """Find an active (starting/running) scan for a given target."""
        with self._lock:
            for inst in self._scans.values():
                if inst.target_id == target_id and inst.status in {"starting", "running"}:
                    return inst
        return None

    def get_capacity(self) -> tuple[int, int]:
        """Return ``(active_count, max_concurrent)``."""
        with self._lock:
            active = sum(1 for s in self._scans.values() if s.status in {"starting", "running"})
        return active, self._max_concurrent

    def cleanup_completed(self) -> int:
        """Remove finished/failed/stopped scans from the tracking dict.

        Returns the number of scans removed.
        """
        terminal = {"completed", "failed", "stopped"}
        removed = 0
        with self._lock:
            to_remove = [sid for sid, inst in self._scans.items() if inst.status in terminal]
            for sid in to_remove:
                del self._scans[sid]
                removed += 1
        if removed:
            logger.info("Cleaned up %d completed scan(s)", removed)
        return removed

    def shutdown_all(self) -> None:
        """Stop all running scans and wait for threads to finish."""
        logger.info("Shutting down all scans...")
        with self._lock:
            scan_ids = list(self._scans.keys())

        for scan_id in scan_ids:
            self.stop_scan(scan_id)

        # Wait briefly for threads to wind down (short timeout — don't block caller)
        with self._lock:
            threads = [
                inst.thread
                for inst in self._scans.values()
                if inst.thread is not None and inst.thread.is_alive()
            ]

        for t in threads:
            t.join(timeout=2)

        logger.info("All scans shut down")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fire_event(self, event_type: str, instance: ScanInstance) -> None:
        """Invoke the on_scan_event callback if set."""
        callback = self.on_scan_event
        if callback is None:
            return
        try:
            callback(
                event_type,
                {
                    "scan_id": instance.scan_id,
                    "target_id": instance.target_id,
                    "target_name": instance.target_name,
                    "status": instance.status,
                    "started_at": instance.started_at,
                    "error": instance.error,
                },
            )
        except Exception:  # noqa: BLE001
            logger.debug("on_scan_event callback raised", exc_info=True)

    @staticmethod
    def _find_root_agent(coordinator: AgentCoordinator) -> str | None:
        """Find the root agent (parent_id is None) in the coordinator."""
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                return aid
        return None

    def _build_run_config(
        self,
        *,
        target_id: str,
        target_name: str,
        target_type: str,
        target_record: dict[str, Any],
        scan_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the ``scan_config`` dict that ``run_prometheus_scan`` expects."""
        from prometheus.interface.defaults import DEFAULT_SKILLS

        # Check if the target_config has a pre-built targets_list (from --scans-file)
        target_config = target_record.get("target_config") or {}
        prebuilt_targets = target_config.get("targets_list")

        if prebuilt_targets:
            # Use the full targets list from scans-file registration
            targets: list[dict[str, Any]] = prebuilt_targets
        else:
            # Build a single target entry from the registry record
            target_entry: dict[str, Any] = {
                "type": target_type,
                "original": target_name,
            }

            # Enrich with details from the target record
            if target_type in {"url", "domain"}:
                target_entry["value"] = target_name
                target_entry["details"] = target_config
            elif target_type in {"repository", "local_code"}:
                target_entry["details"] = target_config
            else:
                target_entry["details"] = target_config

            targets = [target_entry]

        user_instructions = (
            scan_config.get("user_instructions") or scan_config.get("instructions") or ""
        )

        return {
            "targets": targets,
            "user_instructions": user_instructions,
            "skills": scan_config.get("skills") or list(DEFAULT_SKILLS),
            "non_interactive": True,  # orchestrator scans are always non-interactive
            "custom_headers": scan_config.get("custom_headers") or [],
            "local_sources": scan_config.get("local_sources") or [],
            "diff_scope": {"active": False},
            "resume_instruction": "",
            "scope_mode": "auto",
            "diff_base": None,
            "tech_stack": scan_config.get("tech_stack") or [],
            "scan_config": scan_config,
        }


def get_orchestrator() -> ScanOrchestrator:
    """Convenience accessor for the singleton."""
    return ScanOrchestrator()
