"""Agent-facing cross-target intelligence tools.

These tools let the prometheus agent discover relationships between scan targets
based on shared technologies, surface vulnerability patterns from similar
targets, and transfer successful techniques across targets.
"""

from __future__ import annotations

import asyncio
import json
import logging

from agents import RunContextWrapper, function_tool

from prometheus.core.cross_target import CrossTargetIntel


logger = logging.getLogger(__name__)


def _intel() -> CrossTargetIntel:
    return CrossTargetIntel()


@function_tool(timeout=30)
async def get_cross_target_suggestions(
    ctx: RunContextWrapper,
    domain: str,
) -> str:
    """Get intelligence suggestions from other targets sharing technology.

    Scans all active targets for technology overlap with the given domain,
    then surfaces:
    - Vulnerability patterns found on similar targets
    - Successful attack techniques that may transfer
    - Failed approaches to avoid wasting time on

    Call this early in a scan to leverage knowledge from prior scans on
    related targets.

    Args:
        domain: Target domain to get suggestions for (e.g. ``example.com``).
    """
    try:
        suggestions = await asyncio.to_thread(
            _intel().get_cross_target_suggestions,
            domain=domain,
        )
        if not suggestions:
            return json.dumps(
                {
                    "domain": domain,
                    "suggestions": [],
                    "message": "No cross-target suggestions found. Either no other targets share technology, or no prior knowledge exists.",
                }
            )
        return json.dumps(
            {
                "domain": domain,
                "suggestion_count": len(suggestions),
                "suggestions": suggestions,
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:
        logger.exception("get_cross_target_suggestions failed")
        return json.dumps({"success": False, "error": str(exc)})


@function_tool(timeout=30)
async def get_tech_overlap(
    ctx: RunContextWrapper,
    domain: str,
) -> str:
    """Find other targets that share technology with the given domain.

    Compares the technology stack of the given domain against all other
    active targets in the registry. Returns a list of targets with their
    shared technologies and overlap count.

    Useful for identifying targets that might share vulnerabilities or
    where techniques from one target could apply to another.

    Args:
        domain: Target domain to check (e.g. ``example.com``).
    """
    try:
        overlap = await asyncio.to_thread(
            _intel().get_tech_overlap,
            domain=domain,
        )
        if not overlap:
            return json.dumps(
                {
                    "domain": domain,
                    "overlap": [],
                    "message": "No technology overlap found with other targets.",
                }
            )
        return json.dumps(
            {
                "domain": domain,
                "overlapping_targets": len(overlap),
                "overlap": overlap,
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:
        logger.exception("get_tech_overlap failed")
        return json.dumps({"success": False, "error": str(exc)})
