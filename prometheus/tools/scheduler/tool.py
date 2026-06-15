"""Agent-facing scheduler tools.

These tools let the prometheus agent inspect and modify scan schedules:
get, set, pause, and resume per-target schedules.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


def _scheduler() -> Any:
    from prometheus.core.scheduler import ScanScheduler

    return ScanScheduler()


def _registry() -> Any:
    from prometheus.core.target_registry import TargetRegistry

    return TargetRegistry()


# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------


@function_tool(timeout=30)
async def get_schedule(
    ctx: RunContextWrapper,
    target_id: str | None = None,
) -> str:
    """Get scan schedule information for one or all targets.

    Args:
        target_id: Optional target ID. If omitted, returns schedules
            for all active targets.
    """
    try:
        sched = await asyncio.to_thread(_scheduler().get_schedule_info)
    except Exception as exc:
        logger.exception("get_schedule failed")
        return json.dumps({"success": False, "error": str(exc)})

    if target_id:
        sched = [s for s in sched if s["target_id"] == target_id]
        if not sched:
            return json.dumps(
                {"success": False, "error": f"Target '{target_id}' not found or has no schedule"}
            )

    return json.dumps(
        {"success": True, "schedules": sched},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def set_schedule(
    ctx: RunContextWrapper,
    target_id: str,
    interval_hours: int,
) -> str:
    """Set the scan interval for a target.

    Args:
        target_id: The target's unique ID.
        interval_hours: Hours between scans (minimum 1).
    """
    try:
        scheduler = _scheduler()
        await asyncio.to_thread(scheduler.set_schedule, target_id, interval_hours)

        # Also persist in registry
        registry = _registry()
        await asyncio.to_thread(registry.update_target, target_id, interval_hours=interval_hours)
    except Exception as exc:
        logger.exception("set_schedule failed")
        return json.dumps({"success": False, "error": str(exc)})

    return json.dumps(
        {"success": True, "target_id": target_id, "interval_hours": interval_hours},
        ensure_ascii=False,
    )


@function_tool(timeout=30)
async def pause_schedule(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Pause scheduled scanning for a target.

    The target remains in the registry but the scheduler will not
    launch new scans for it until resumed.

    Args:
        target_id: The target's unique ID.
    """
    try:
        scheduler = _scheduler()
        await asyncio.to_thread(scheduler.pause_schedule, target_id)
    except Exception as exc:
        logger.exception("pause_schedule failed")
        return json.dumps({"success": False, "error": str(exc)})

    return json.dumps(
        {"success": True, "target_id": target_id, "status": "paused"},
        ensure_ascii=False,
    )


@function_tool(timeout=30)
async def resume_schedule(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Resume scheduled scanning for a previously paused target.

    Args:
        target_id: The target's unique ID.
    """
    try:
        scheduler = _scheduler()
        await asyncio.to_thread(scheduler.resume_schedule, target_id)
    except Exception as exc:
        logger.exception("resume_schedule failed")
        return json.dumps({"success": False, "error": str(exc)})

    return json.dumps(
        {"success": True, "target_id": target_id, "status": "resumed"},
        ensure_ascii=False,
    )
