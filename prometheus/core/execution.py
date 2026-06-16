"""Execution loop for addressable SDK-backed prometheus agents."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import httpx
from agents import RunConfig, Runner
from agents.exceptions import AgentsException, MaxTurnsExceeded, UserError
from agents.stream_events import RunItemStreamEvent
from openai import APIConnectionError, APIError

from prometheus.core.comms import get_active_run, write_status
from prometheus.core.inputs import child_initial_input
from prometheus.core.sessions import open_agent_session, strip_latest_image_from_session
from prometheus.core.context_manager import create_context_managed_session


if TYPE_CHECKING:
    from pathlib import Path

    from agents.lifecycle import RunHooks
    from agents.memory import Session, SQLiteSession
    from agents.result import RunResultBase
    from agents.items import TResponseInputItem  # codeql[py/unused-import] : re-exported for the agents SDK consumers; remove when SDK stops importing it

    from prometheus.core.agents import AgentCoordinator, Status


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]

_INPUT_REJECTION_CODES = frozenset({400, 404, 422})

# Context cap: ~50K tokens, assuming 4 chars per token
_CHARS_PER_TOKEN = 4
_MAX_TASK_CHARS = 50_000 * _CHARS_PER_TOKEN

# --- Fix 1: stagger child-agent spawns so they don't all hit the API ---
# at the same instant.  The lock serialises spawns; the sleep gives each
# child a head-start before the next one begins its first API call.
_spawn_lock = asyncio.Lock()
_CHILD_SPAWN_STAGGER_SECONDS = 3.0

# --- Fix 3: retry child-agent runs on provider (API) errors ---
_provider_error_retries: dict[str, int] = {}
_PROVIDER_ERROR_MAX_RETRIES = 5
_PROVIDER_ERROR_BASE_DELAY = 3.0  # seconds; backs off 3 → 6 → 12 → 24 → 48

# --- Fix: track agents that exhausted provider error retries (prevents Fix 3/6 cascade) ---
_provider_error_exhausted: set[str] = set()

# --- Fix 4: retry on transport errors (mid-stream connection drops) ---
_TRANSPORT_ERROR_TYPES = (
    httpx.RemoteProtocolError,
    httpx.ReadError,
    httpx.ConnectError,
    APIConnectionError,
    TimeoutError,  # Fix 5: stream stall watchdog (asyncio.timeout)
)
_TRANSPORT_ERROR_MAX_RETRIES = 5
_TRANSPORT_ERROR_BASE_DELAY = 3.0  # seconds; backs off 3 → 6 → 12 → 24 → 48
_transport_error_retries: dict[str, int] = {}

# Retry for "Prepared model input is empty" — SDK session compaction edge case
_EMPTY_INPUT_MAX_RETRIES = 2  # codeql[py/unused-global-variable] : retained for test compatibility (tests/test_empty_input.py asserts the SDK path doesn't reference it)
_EMPTY_INPUT_RETRY_DELAY = 2.0  # seconds; backs off 2 → 4
_empty_input_retries: dict[str, int] = {}

# --- Fix 2A: per-agent stream-event-sink health tracking ---
# When the sink (typically an IPC writer) dies, every subsequent call
# re-raises the same exception and the loop logs the same traceback
# dozens of times. Track per-agent sink health so we mark it dead on
# the first failure and skip subsequent calls (the FIRST failure is
# still logged at WARNING with the traceback).
_sink_dead: set[str] = set()


def _check_event_sink_health(agent_id: str) -> bool:
    """Return True if the per-agent sink is healthy (or no sink was set).

    After the first sink failure for ``agent_id`` the sink is marked
    dead and the loop will skip it for the rest of the scan. This
    kills the "stream event sink failed for X" log spam.
    """
    return agent_id not in _sink_dead


def _mark_sink_dead(agent_id: str) -> None:
    """Mark the per-agent sink as permanently broken.

    The first exception is still logged at WARNING with the traceback
    (caller's responsibility) before calling this; subsequent calls
    are silently skipped to avoid log spam.
    """
    _sink_dead.add(agent_id)


# --- Fix 5: stream stall watchdog ---
# If no stream event arrives within this many seconds, the LLM connection is
# considered dead (CLOSE-WAIT / half-open).  The timeout resets on every event.
_STREAM_STALL_TIMEOUT = 300  # 5 minutes

# --- Circuit breaker: cap child-agent turns to prevent runaway token spend ---
# With the deterministic pipeline handling mechanical recon, child agents
# should complete in 10-20 turns. 60 gives enough runway for deep mode
# on complex targets while still preventing infinite loops.
_MAX_CHILD_TURNS = 60
# Env var override for the child cap.  Allows operators to lift the
# per-child turn budget for long-running programs (e.g. multi-stage
# fuzzing) without code changes.  Must be a positive integer.
_CHILD_MAX_TURNS_ENV = "PROMETHEUS_CHILD_MAX_TURNS"


def _resolve_child_max_turns() -> int:
    """Return the configured child-agent max_turns cap.

    Reads ``PROMETHEUS_CHILD_MAX_TURNS`` from the environment each call
    so a hot-reload (or a wrapper script) can change it without
    restarting the process. Falls back to the compiled-in
    ``_MAX_CHILD_TURNS`` default on missing/invalid values.
    """
    import os

    raw = os.environ.get(_CHILD_MAX_TURNS_ENV, "").strip()
    if not raw:
        return _MAX_CHILD_TURNS
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Ignoring invalid %s=%r (must be a positive integer); using default %d",
            _CHILD_MAX_TURNS_ENV,
            raw,
            _MAX_CHILD_TURNS,
        )
        return _MAX_CHILD_TURNS
    if value < 1:
        logger.warning(
            "Ignoring %s=%d (must be >= 1); using default %d",
            _CHILD_MAX_TURNS_ENV,
            value,
            _MAX_CHILD_TURNS,
        )
        return _MAX_CHILD_TURNS
    return value


_MAX_CONSECUTIVE_ERRORS = 10  # max consecutive same-tool errors before forced stop
# Infrastructure-error threshold is much higher because these are
# transient environment issues (ENOSPC, network, Docker).  Killing the
# agent after 10 retries wastes a whole scan; we let the LLM keep trying
# for ~5 minutes (depends on tool call latency) and only break the
# circuit if the environment is clearly not coming back.
_MAX_CONSECUTIVE_INFRA_ERRORS = 50  # max consecutive infra errors before forced stop
_consecutive_infra_errors: dict[str, int] = {}

# --- Context budget: prevent context window exhaustion ---
# DeepSeek v4 context limit is 1,048,565 tokens.
# At 80% we force compaction to avoid hard crashes.
_CONTEXT_BUDGET_TOKENS = 800_000
_CONTEXT_COMPACT_KEEP_RECENT = 10  # keep the most recent N items during compaction

# Per-child-agent consecutive error tracking: agent_id -> (tool_name, count)
_consecutive_tool_errors: dict[str, tuple[str, int]] = {}

# --- Fix 7: subagent health monitor & auto-respawn ---
# Tracks per-agent activity for stall detection. Updated on every stream event.
_agent_last_activity: dict[str, float] = {}  # agent_id -> monotonic timestamp
_agent_activity_lock = asyncio.Lock()  # codeql[py/unused-global-variable] : reserved for future concurrent updates to _agent_last_activity; harmless when idle

# If no stream event (tool call, text output, anything) within this many
# seconds, the agent is considered stalled — not a dead connection (Fix 5
# handles that), but a live connection where the LLM stopped producing.
_AGENT_STALL_THRESHOLD = 600  # 10 minutes

# Max auto-respawn attempts per agent before giving up.
_MAX_AUTO_RESPAWN = 2

# Per-agent respawn counter.
_respawn_counts: dict[str, int] = {}

# --- Fix 8: WAF/block pattern detection ---
# Track consecutive 403 responses per agent to detect Cloudflare/WAF blocking.
_agent_consecutive_403s: dict[str, int] = {}
_WAF_BLOCK_THRESHOLD = 5  # consecutive 403s before injecting adaptive strategy

# Track agent progress snapshots for respawn context.
# agent_id -> list of recent tool outputs (last N)
_agent_progress_snapshots: dict[str, list[dict[str, str]]] = {}
_MAX_PROGRESS_SNAPSHOTS = 20


def _update_agent_activity(agent_id: str) -> None:
    """Called on every stream event to track agent liveness."""
    _agent_last_activity[agent_id] = time.monotonic()


def _record_progress(agent_id: str, tool_name: str, output_preview: str) -> None:
    """Save tool output snapshots for respawn context."""
    if agent_id not in _agent_progress_snapshots:
        _agent_progress_snapshots[agent_id] = []
    snapshots = _agent_progress_snapshots[agent_id]
    snapshots.append(
        {
            "tool": tool_name,
            "output": output_preview[:500],
            "time": str(time.monotonic()),
        }
    )
    if len(snapshots) > _MAX_PROGRESS_SNAPSHOTS:
        _agent_progress_snapshots[agent_id] = snapshots[-_MAX_PROGRESS_SNAPSHOTS:]


def _detect_waf_block(agent_id: str, output: str) -> bool:
    """Detect WAF/Cloudflare blocking patterns in tool output."""
    block_indicators = [
        "cf-mitigated: challenge",
        "403",
        "access denied",
        "blocked by cloudflare",
        "challenge-platform",
        "cf_chl_opt",
        "ray ID",
    ]
    output_lower = output.lower()
    hits = sum(1 for indicator in block_indicators if indicator in output_lower)
    if hits >= 2:
        count = _agent_consecutive_403s.get(agent_id, 0) + 1
        _agent_consecutive_403s[agent_id] = count
        return count >= _WAF_BLOCK_THRESHOLD
    else:
        _agent_consecutive_403s[agent_id] = 0
        return False


def _build_adaptive_strategy_prompt(agent_id: str) -> str:
    """Build a prompt injection when WAF blocking is detected."""
    return (
        "SELF-HEALING ALERT: You are being blocked by a WAF/Cloudflare. "
        "All recent requests returned 403 or challenge pages. Adapt your strategy:\n"
        "1. Use the browser tool (agent-browser) instead of curl for HTTP requests\n"
        "2. Use Tor bypass mode: prefix commands with #tor-bypass#\n"
        "3. Try different User-Agent headers or request patterns\n"
        "4. Focus on API endpoints that may not have WAF protection\n"
        "5. Check for alternative entry points (mobile APIs, staging environments)\n"
        "6. If all HTTP approaches are blocked, use web_search to find cached/archived versions\n"
        "Do NOT keep retrying the same blocked approach. Switch strategy NOW."
    )


def _build_respawn_context(agent_id: str, task: str) -> str:
    """Build context for a respawned agent including progress from previous attempt."""
    snapshots = _agent_progress_snapshots.get(agent_id, [])
    if not snapshots:
        return task

    progress_lines = []
    for snap in snapshots:
        progress_lines.append(f"  [{snap['tool']}] {snap['output'][:200]}")

    return (
        f"{task}\n\n"
        f"PROGRESS FROM PREVIOUS ATTEMPT (do NOT repeat this work):\n"
        + "\n".join(progress_lines)
        + "\n\nContinue from where you left off. Do not repeat completed steps."
    )


async def auto_respawn_child(
    coordinator: Any,
    agent_id: str,
    parent_ctx: dict[str, Any],
) -> bool:
    """Attempt to auto-respawn a crashed/failed child agent.

    Checks eligibility (status in crashed/failed, respawn count < max),
    increments the counter, retrieves the original task from coordinator
    metadata, builds respawn context with progress from the previous
    attempt, and uses the parent context spawner to create a new agent.

    Returns True if respawn was attempted, False if not eligible.
    """
    async with coordinator._lock:
        status = coordinator.statuses.get(agent_id)
        md = dict(coordinator.metadata.get(agent_id, {}))

    if status not in {"crashed", "failed"}:
        logger.debug(
            "auto_respawn_child: %s not eligible (status=%s)",
            agent_id,
            status,
        )
        return False

    respawns = _respawn_counts.get(agent_id, 0)
    if respawns >= _MAX_AUTO_RESPAWN:
        logger.warning(
            "auto_respawn_child: %s max respawns (%d) exhausted",
            agent_id,
            _MAX_AUTO_RESPAWN,
        )
        return False

    _respawn_counts[agent_id] = respawns + 1
    original_task = str(md.get("task", ""))
    respawn_task = _build_respawn_context(agent_id, original_task)
    name = md.get("name", agent_id)

    logger.info(
        "auto_respawn_child: respawning %s (%s) attempt %d/%d, task_len=%d",
        name,
        agent_id,
        respawns + 1,
        _MAX_AUTO_RESPAWN,
        len(respawn_task),
    )

    write_status(
        get_active_run() or "",
        "agent_auto_respawn",
        {
            "agent_id": agent_id,
            "name": name,
            "status": status,
            "attempt": respawns + 1,
        },
    )

    # Notify parent
    root_id = parent_ctx.get("agent_id")
    if root_id:
        await coordinator.send(
            root_id,
            {
                "from": agent_id,
                "type": "instruction",
                "priority": "high",
                "content": (
                    f"[Auto-respawn] {name} ({agent_id}) was {status}. "
                    f"Attempt {respawns + 1}/{_MAX_AUTO_RESPAWN}: "
                    f"respawning with progress context. "
                    f"Previous task: {original_task[:200]}"
                ),
            },
        )

    # Use spawner from parent context if available
    spawner = parent_ctx.get("spawn_child_agent")
    if spawner:
        try:
            await spawner(
                name=name,
                task=respawn_task,
                skills=list(md.get("skills") or []),
                parent_ctx=parent_ctx,
            )
            logger.info(
                "auto_respawn_child: successfully respawned %s (%s)",
                name,
                agent_id,
            )
            return True
        except Exception:
            logger.exception(
                "auto_respawn_child: spawner failed for %s (%s)",
                name,
                agent_id,
            )
            return False
    else:
        logger.warning(
            "auto_respawn_child: no spawn_child_agent in parent_ctx; cannot respawn %s (%s)",
            name,
            agent_id,
        )
        return False


async def _monitor_agent_health(
    coordinator: Any,
    parent_ctx: dict[str, Any],
) -> None:
    """Background task that monitors all running child agents for stalls.

    Runs every 60s. For each child agent:
    - Running agents: checks if last activity was > _AGENT_STALL_THRESHOLD seconds ago
      and sends a nudge if stalled
    - Crashed/failed agents: attempts auto-respawn if under the max respawn limit
    - Stopped agents: notifies parent suggesting they check or respawn

    This task is created as a background asyncio task and runs until the
    scan completes.
    """
    root_id = parent_ctx.get("agent_id")
    if root_id is None:
        return

    logger.info("[health_monitor] Started for root agent %s", root_id)

    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            now = time.monotonic()
            async with coordinator._lock:
                agents_snapshot = [
                    (aid, status, coordinator.names.get(aid, aid))
                    for aid, status in coordinator.statuses.items()
                    if aid != root_id and status in {"running", "crashed", "failed", "stopped"}
                ]

            for aid, status, name in agents_snapshot:
                # --- Handle crashed/failed agents: auto-respawn ---
                if status in {"crashed", "failed"}:
                    respawns = _respawn_counts.get(aid, 0)
                    if respawns < _MAX_AUTO_RESPAWN:
                        logger.warning(
                            "[health_monitor] Agent %s (%s) is %s (attempt %d/%d). "
                            "Auto-respawning.",
                            name,
                            aid,
                            status,
                            respawns + 1,
                            _MAX_AUTO_RESPAWN,
                        )
                        write_status(
                            get_active_run() or "",
                            "agent_auto_respawn",
                            {
                                "agent_id": aid,
                                "name": name,
                                "status": status,
                                "attempt": respawns + 1,
                            },
                        )
                        _respawn_counts[aid] = respawns + 1
                        # Build respawn context from progress snapshots
                        try:
                            async with coordinator._lock:
                                md = dict(coordinator.metadata.get(aid, {}))
                            original_task = str(md.get("task", ""))
                            respawn_task = _build_respawn_context(aid, original_task)
                            # Notify parent about the respawn
                            parent = md.get("_parent_id") or parent_ctx.get("agent_id")
                            if parent:
                                await coordinator.send(
                                    parent,
                                    {
                                        "from": aid,
                                        "type": "instruction",
                                        "priority": "high",
                                        "content": (
                                            f"[Auto-respawn] {name} ({aid}) was {status}. "
                                            f"Attempt {respawns + 1}/{_MAX_AUTO_RESPAWN}: "
                                            f"respawning with progress context. "
                                            f"Previous task: {original_task[:200]}"
                                        ),
                                    },
                                )
                            # Attempt to use parent_ctx spawner if available
                            spawner = parent_ctx.get("spawn_child_agent")
                            if spawner:
                                await spawner(
                                    name=name,
                                    task=respawn_task,
                                    skills=list(md.get("skills") or []),
                                    parent_ctx=parent_ctx,
                                )
                                logger.info(
                                    "[health_monitor] Respawned %s (%s) via spawner "
                                    "(attempt %d/%d)",
                                    name,
                                    aid,
                                    respawns + 1,
                                    _MAX_AUTO_RESPAWN,
                                )
                            else:
                                logger.warning(
                                    "[health_monitor] No spawner available in parent_ctx "
                                    "for respawning %s (%s). Marking for manual respawn.",
                                    name,
                                    aid,
                                )
                        except Exception:
                            logger.exception(
                                "[health_monitor] Auto-respawn failed for %s (%s)",
                                name,
                                aid,
                            )
                    else:
                        logger.warning(
                            "[health_monitor] Agent %s (%s) is %s but max respawns (%d) "
                            "exhausted. No further auto-respawn.",
                            name,
                            aid,
                            status,
                            _MAX_AUTO_RESPAWN,
                        )
                    continue

                # --- Handle stopped agents (hit turn limit): notify parent ---
                if status == "stopped":
                    try:
                        async with coordinator._lock:
                            parent = coordinator.parent_of.get(aid)
                        if parent:
                            await coordinator.send(
                                parent,
                                {
                                    "from": aid,
                                    "type": "instruction",
                                    "priority": "normal",
                                    "content": (
                                        f"[Agent stopped] {name} ({aid}) hit its turn/circuit "
                                        f"limit and stopped. Consider checking its progress "
                                        f"or respawning it to continue the task."
                                    ),
                                },
                            )
                    except Exception:
                        logger.exception(
                            "[health_monitor] Failed to notify parent about stopped agent %s",
                            aid,
                        )
                    continue

                # --- Running agents: check for stalls ---
                last_active = _agent_last_activity.get(aid)
                if last_active is None:
                    continue

                idle_seconds = now - last_active
                if idle_seconds < _AGENT_STALL_THRESHOLD:
                    continue

                # Agent is stalled — send a nudge
                logger.warning(
                    "[health_monitor] Agent %s (%s) stalled for %.0fs (threshold: %ds). Sending nudge.",
                    name,
                    aid,
                    idle_seconds,
                    _AGENT_STALL_THRESHOLD,
                )

                write_status(
                    get_active_run() or "",
                    "agent_stall_detected",
                    {"agent_id": aid, "name": name, "idle_seconds": idle_seconds},
                )

                # Send a nudge message to wake the agent
                await coordinator.send(
                    aid,
                    {
                        "from": root_id,
                        "type": "instruction",
                        "priority": "urgent",
                        "content": (
                            f"STALL DETECTED: You have been idle for {int(idle_seconds)}s. "
                            "You MUST call a tool immediately — either continue your task "
                            "or call agent_finish if you are blocked. Do NOT produce text "
                            "without tool calls. If you are blocked by Cloudflare/WAF, "
                            "switch to browser-based approach or save_knowledge and finish."
                        ),
                    },
                )

                # Update activity timestamp so we don't nudge again immediately
                _agent_last_activity[aid] = now

                # Check WAF blocking patterns
                if _agent_consecutive_403s.get(aid, 0) >= _WAF_BLOCK_THRESHOLD:
                    adaptive_prompt = _build_adaptive_strategy_prompt(aid)
                    await coordinator.send(
                        aid,
                        {
                            "from": root_id,
                            "type": "instruction",
                            "priority": "urgent",
                            "content": adaptive_prompt,
                        },
                    )
                    logger.warning(
                        "[health_monitor] Injected WAF adaptive strategy for %s (%s)",
                        name,
                        aid,
                    )

            # Compact the root agent's session — keeps recent tool pairs,
            # compresses older operations into a summary. Only triggers when
            # there are enough items to warrant compaction (prevents aggressive
            # trimming that loses scan data). Uses a larger keep window for
            # deep scans so findings aren't discarded too early.
            try:
                compacted = await coordinator.compact_root_session(keep_turns=30)
                if compacted > 0:
                    logger.info("[health_monitor] Compacted root session")
            except Exception:
                logger.debug("[health_monitor] Root session compaction failed", exc_info=True)

        except asyncio.CancelledError:
            logger.info("[health_monitor] Cancelled, shutting down")
            return
        except Exception:
            logger.exception("[health_monitor] Error in health check loop")
            await asyncio.sleep(10)


async def run_agent_loop(
    *,
    agent: Any,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
    session: Session | None = None,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> RunResultBase | None:
    await coordinator.attach_runtime(
        agent_id,
        session=session,
        interrupt_on_message=interactive,
    )
    result: RunResultBase | None = None

    # --- Fix 7: start health monitor for root agent (monitors all children) ---
    _health_monitor_task: asyncio.Task[None] | None = None
    if context.get("parent_id") is None:
        _health_monitor_task = asyncio.create_task(
            _monitor_agent_health(coordinator, context),
            name=f"health-monitor-{agent_id}",
        )

    try:
        if not (start_parked and interactive):
            if interactive:
                result = await _run_cycle(
                    agent,
                    coordinator,
                    agent_id,
                    input_data=initial_input,
                    run_config=run_config,
                    context=context,
                    max_turns=max_turns,
                    session=session,
                    interactive=interactive,
                    event_sink=event_sink,
                    hooks=hooks,
                )
            else:
                result = await _run_noninteractive_until_lifecycle(
                    agent,
                    coordinator,
                    agent_id,
                    initial_input=initial_input,
                    run_config=run_config,
                    context=context,
                    max_turns=max_turns,
                    session=session,
                    event_sink=event_sink,
                    hooks=hooks,
                )

        if not interactive:
            return result

        while True:
            try:
                await coordinator.wait_for_message(agent_id)
            except asyncio.CancelledError:
                return result

            # Don't process messages if agent is in a terminal state
            async with coordinator._lock:
                current_status = coordinator.statuses.get(agent_id)
            if current_status not in (None, "running", "waiting"):
                logger.info(
                    "[agent %s] status is %s; breaking message loop",
                    agent_id,
                    current_status,
                )
                return result

            await coordinator.consume_pending(agent_id)
            result = await _run_cycle(
                agent,
                coordinator,
                agent_id,
                input_data=[],
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
            )
    finally:
        # Clean up health monitor on exit
        if _health_monitor_task is not None:
            _health_monitor_task.cancel()  # codeql[py/ineffectual-statement] : cancel() returns None but mutates the task's state machine; await below reaps it
            with contextlib.suppress(asyncio.CancelledError):
                await _health_monitor_task  # codeql[py/ineffectual-statement] : the coroutine result is intentionally discarded; we only need the CancelledError to be suppressed


async def spawn_child_agent(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    name: str,
    task: str,
    skills: list[str],
    parent_history: list[Any] | None = None,  # deprecated; ignored
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    logger.debug(
        "spawn_child_agent: name=%s task_len=%d skills=%s interactive=%s",
        name,
        len(task),
        skills,
        interactive,
    )
    if len(task) > _MAX_TASK_CHARS:
        logger.warning(
            "spawn_child_agent: truncating task for '%s' from %d to %d chars (~%d tokens)",
            name,
            len(task),
            _MAX_TASK_CHARS,
            _MAX_TASK_CHARS // _CHARS_PER_TOKEN,
        )
        task = task[:_MAX_TASK_CHARS] + "\n\n[Task description truncated to fit context window]"

    parent_id = parent_ctx.get("agent_id")
    if not isinstance(parent_id, str):
        raise TypeError("Parent agent_id missing from context")

    child_id = uuid.uuid4().hex[:8]
    child_agent = factory(name=name, skills=skills)
    await coordinator.register(
        child_id,
        name,
        parent_id,
        task=task,
        skills=skills,
    )
    # Live observability: tell the tailer a new agent just came online.
    # Best-effort, never raises — a missing comms file shouldn't kill a scan.
    try:
        _spawn_run_id = get_active_run()
        if _spawn_run_id:
            write_status(
                _spawn_run_id,
                "agent_spawn",
                {
                    "agent_id": child_id,
                    "name": name,
                    "parent_id": parent_id,
                    "skills": list(skills or []),
                    "task_preview": (task or "")[:200],
                },
            )
    except Exception:
        logger.debug("agent_spawn write_status failed", exc_info=True)

    # Fix 1: stagger child spawns so concurrent create_agent calls don't
    # all fire their first API request at the same instant.
    async with _spawn_lock:
        await asyncio.sleep(_CHILD_SPAWN_STAGGER_SECONDS)
        await _start_child_runner(
            parent_ctx=parent_ctx,
            coordinator=coordinator,
            agents_db_path=agents_db_path,
            sessions_to_close=sessions_to_close,
            run_config=run_config,
            max_turns=max_turns,
            interactive=interactive,
            child_agent=child_agent,
            child_id=child_id,
            name=name,
            parent_id=parent_id,
            task=task,
            initial_input=child_initial_input(
                name=name,
                child_id=child_id,
                parent_id=parent_id,
                task=task,
            ),
            event_sink=event_sink,
            hooks=hooks,
        )

    return {
        "success": True,
        "agent_id": child_id,
        "name": name,
        "parent_id": parent_id,
        "message": f"Spawned '{name}' ({child_id}) running in parallel.",
    }


async def respawn_subagents(
    *,
    coordinator: AgentCoordinator,
    factory: Any,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    parent_ctx: dict[str, Any],
    root_id: str,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    async with coordinator._lock:
        agents_snapshot = [
            (aid, status, dict(coordinator.metadata.get(aid, {})))
            for aid, status in coordinator.statuses.items()
        ]
        candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
        for aid, status, md in agents_snapshot:
            if not interactive and status not in {"running", "waiting"}:
                continue
            if coordinator.parent_of.get(aid) is None or aid == root_id:
                continue
            md["_restored_status"] = status
            candidates.append(
                (
                    aid,
                    coordinator.names.get(aid, aid),
                    coordinator.parent_of.get(aid),
                    md,
                )
            )

    for child_id, name, parent_id, md in candidates:
        try:
            restored_status = str(md.get("_restored_status") or "running")
            start_parked = interactive and restored_status != "running"

            if start_parked:
                logger.warning(
                    "respawn %s (%s): starting parked from status=%s",
                    child_id,
                    name,
                    restored_status,
                )

            child_skills = list(md.get("skills") or [])
            child_agent = factory(name=name, skills=child_skills)
            await _start_child_runner(
                parent_ctx=parent_ctx,
                coordinator=coordinator,
                agents_db_path=agents_db_path,
                sessions_to_close=sessions_to_close,
                run_config=run_config,
                max_turns=max_turns,
                interactive=interactive,
                child_agent=child_agent,
                child_id=child_id,
                name=name,
                parent_id=parent_id,
                task=str(md.get("task", "")),
                initial_input=[],
                start_parked=start_parked,
                event_sink=event_sink,
                hooks=hooks,
            )
            logger.info(
                "respawned %s (%s) parent=%s task_len=%d",
                child_id,
                name,
                parent_id or "-",
                len(md.get("task", "")),
            )
        except Exception:
            logger.exception("respawn %s failed; marking crashed", child_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(child_id, "crashed")


def _maybe_create_goal_from_result(
    result: RunResultBase | None,
    goal_manager: Any,
) -> None:
    """Check if the agent just filed a finding; if so, create a discovery goal."""
    if result is None:
        return

    # Look for create_vulnerability_report tool calls in the result
    new_items = getattr(result, "new_items", None)
    if not new_items:
        return

    from prometheus.core.scan_goals import classify_finding_type

    for item in new_items:
        # Check for function call outputs from create_vulnerability_report
        item_type = getattr(item, "type", "")
        if item_type != "function_call_output":
            continue

        output = getattr(item, "output", "")

        # Check if this is from create_vulnerability_report
        if not isinstance(output, str):
            continue

        # Look for successful finding creation (the tool returns JSON with success=True and a title)
        try:
            import json as _json

            data = _json.loads(output) if output.startswith("{") else {}
        except (ValueError, TypeError):
            continue

        if not data.get("success") or not data.get("title"):
            continue

        # Check if we already have a goal for this finding
        title = data["title"]
        endpoint = data.get("endpoint", "")
        existing = goal_manager.get_active_goal()
        if existing and existing.finding_title == title:
            continue  # already tracking this

        # Create a discovery goal
        finding_type = classify_finding_type(title, data.get("description", ""))
        _ = goal_manager.create_goal(
            {
                "title": title,
                "description": data.get("description", ""),
                "endpoint": endpoint,
                "finding_type": finding_type,
            }
        )
        logger.info(
            "Created discovery goal for finding: %s (type=%s, endpoint=%s)",
            title,
            finding_type,
            endpoint,
        )
        goal_manager.persist()


async def _run_noninteractive_until_lifecycle(
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    initial_input: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    """Non-chat mode keeps running until finish_scan / agent_finish settles status."""
    result: RunResultBase | None = None
    input_data: Any = initial_input
    invalid_final_outputs = 0
    invalid_final_output_limit = max(1, max_turns)

    run_id = get_active_run()
    turn_counter = 0
    while True:
        turn_counter += 1
        if run_id:
            write_status(run_id, "turn_start", {"turn": turn_counter, "agent_id": agent_id})
        result = await _run_cycle(
            agent,
            coordinator,
            agent_id,
            input_data=input_data,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            session=session,
            interactive=False,
            event_sink=event_sink,
            hooks=hooks,
        )

        # --- DISCOVERY GOAL EVALUATION (root agent only) ---
        goal_manager = context.get("goal_manager")
        if goal_manager and context.get("parent_id") is None:
            try:
                from prometheus.core.scan_goals import generate_continuation_prompt, judge_scan_goal

                # Check if a finding was just filed — create goal if so
                _maybe_create_goal_from_result(result, goal_manager)

                active_goal = goal_manager.get_active_goal()
                if active_goal:
                    last_output = _final_output_preview(result)
                    verdict = judge_scan_goal(active_goal, last_output)
                    if verdict.get("done"):
                        poc_status = verdict.get("poc_status", "working")
                        reason = verdict.get("reason", "")
                        goal_manager.complete_goal(
                            active_goal.id,
                            status="validated" if poc_status == "working" else "dead_end",
                            poc_status=poc_status,
                            dead_end_reason="" if poc_status == "working" else reason,
                        )
                        goal_manager.persist()
                        logger.info(
                            "Discovery goal completed: %s (status=%s, poc=%s)",
                            active_goal.finding_title,
                            "validated" if poc_status == "working" else "dead_end",
                            poc_status,
                        )
                    else:
                        # Goal not done — inject continuation prompt
                        continuation = generate_continuation_prompt(active_goal)
                        active_goal.attempts += 1
                        if active_goal.attempts in active_goal.continuation_history:
                            pass  # avoid duplicates
                        else:
                            active_goal.continuation_history.append(continuation[:200])
                        goal_manager.persist()
                        logger.info(
                            "Discovery goal not done (attempt %d/%d): %s — injecting continuation",
                            active_goal.attempts,
                            active_goal.max_attempts,
                            active_goal.finding_title,
                        )
                        input_data = continuation
                        if active_goal.attempts >= active_goal.max_attempts:
                            goal_manager.complete_goal(
                                active_goal.id,
                                status="abandoned",
                                dead_end_reason=f"Max attempts ({active_goal.max_attempts}) reached",
                            )
                            goal_manager.persist()
                            logger.warning(
                                "Discovery goal abandoned: %s", active_goal.finding_title
                            )
                        continue  # skip the invalid_final_outputs counter
            except Exception as exc:
                logger.warning("Goal evaluation failed (non-fatal): %s", exc, exc_info=True)

        # If the SDK returned a final_output, check whether it came from a
        # lifecycle tool (finish_scan / agent_finish). Text outputs without
        # a successful lifecycle call are treated as invalid and re-prompted.
        if getattr(result, "final_output", None) is not None:
            status = await _agent_status(coordinator, agent_id)
            if status == "completed":
                logger.info(
                    "agent %s: SDK returned final_output — agent finished via lifecycle tool",
                    agent_id,
                )
                return result
            # Text output without lifecycle completion — don't accept it
            logger.warning(
                "agent %s: text output without successful lifecycle tool call — re-prompting",
                agent_id,
            )

        status = await _agent_status(coordinator, agent_id)
        if status != "running":
            return result

        invalid_final_outputs += 1
        logger.warning(
            "agent %s produced non-lifecycle final output in non-interactive mode; "
            "forcing tool continuation (%d/%d): %s",
            agent_id,
            invalid_final_outputs,
            invalid_final_output_limit,
            _final_output_preview(result),
        )

        if invalid_final_outputs >= invalid_final_output_limit:
            await coordinator.set_status(agent_id, "crashed")
            await _notify_parent_on_terminal(coordinator, agent_id, "crashed")
            raise MaxTurnsExceeded(
                "Agent exhausted non-interactive recovery attempts without calling "
                "finish_scan or agent_finish."
            )

        input_data = await _append_noninteractive_tool_required_message(
            session=session,
            context=context,
            attempt=invalid_final_outputs,
            limit=invalid_final_output_limit,
        )


class ChildAgentCircuitBreakerError(AgentsException):
    """Raised when a child agent hits the consecutive-same-tool-error limit."""


def _check_consecutive_tool_errors(
    agent_id: str,
    event: RunItemStreamEvent,
) -> None:
    """Track consecutive calls to the same tool; raise if the limit is hit.

    This catches runaway retry loops where the LLM keeps calling the same
    failing tool (e.g. nuclei) without making progress.

    Infrastructure errors (ENOSPC, network, Docker daemon stuck) are
    tracked separately under ``_consecutive_infra_errors`` and only
    count against a much higher threshold, with backoff between retries.
    Killing the agent after 10 transient disk-full errors wastes an
    entire scan for an environment problem the LLM cannot fix.
    """
    if event.name == "tool_called":
        new_tool = _extract_tool_name(event)
        prev_tool, count = _consecutive_tool_errors.get(agent_id, ("", 0))
        # Preserve count if same tool; reset if different tool
        _consecutive_tool_errors[agent_id] = (new_tool, count if new_tool == prev_tool else 0)

    elif event.name == "tool_output":
        tool_name, count = _consecutive_tool_errors.get(agent_id, ("", 0))
        if not tool_name:
            return
        output = getattr(event.item, "output", "")
        # Three-way classification: gate-block is NOT an error (LLM is
        # following the protocol) and is handled separately. Logical and
        # infra errors both count against the breaker, but with different
        # thresholds and counter buckets.
        # NOTE: callers in the historic test suite call this function
        # via the bool-returning shim; we need the str kind here to
        # distinguish logical / gate / None.
        kind = _is_tool_output_error_kind(output)
        is_gate = kind == "gate"
        is_infra = _is_infrastructure_error(output) if not is_gate else False
        is_logical_error = kind == "logical" and not is_infra
        if is_gate:
            # Gate-block: the LLM called finish_scan correctly but the gate
            # refused. This is a third category — neither a tool error nor
            # an infra error. The LLM did the right thing. Track the
            # consecutive count per (agent, gate) for the escape hatch but
            # do NOT count it against the tool-error circuit breaker (the
            # old code conflated these and killed agents for following
            # protocol, which is what caused the 12-min stall we observed
            # in a representative gate-confusion scan.
            gate_name = _classify_gate_block(output) or "unknown"
            refusal_count = _record_gate_block(agent_id, gate_name)
            if refusal_count >= _MAX_CONSECUTIVE_GATE_BLOCKS:
                logger.warning(
                    "[agent %s] gate '%s' has refused %d times — escape "
                    "hatch open: next finish_scan will be allowed through "
                    "with a warning.",
                    agent_id,
                    gate_name,
                    refusal_count,
                )
            return
        if is_infra:
            # Infra errors do NOT increment the logical-error counter that
            # would kill the agent.  Instead, we track them under their own
            # (much higher) threshold and warn loudly so operators see it.
            infra_count = _consecutive_infra_errors.get(agent_id, 0) + 1
            _consecutive_infra_errors[agent_id] = infra_count
            if infra_count >= _MAX_CONSECUTIVE_INFRA_ERRORS:
                # Truly unrecoverable: same tool, same infra error, many
                # times in a row.  Surface it as a circuit break.
                _consecutive_tool_errors.pop(agent_id, None)
                _consecutive_infra_errors.pop(agent_id, None)
                raise ChildAgentCircuitBreakerError(
                    f"Tool '{tool_name}' hit infrastructure error "
                    f"({_classify_infra_error(output)}) {infra_count} consecutive "
                    f"times — stopping. Check disk, network, and Docker."
                )
            if infra_count in (3, 10, 25):
                # Periodic operator-visible warning; don't spam on every call.
                logger.warning(
                    "[agent %s] Infrastructure error from '%s' x%d: %s. "
                    "Continuing (will circuit-break at %d).",
                    agent_id,
                    tool_name,
                    infra_count,
                    _classify_infra_error(output),
                    _MAX_CONSECUTIVE_INFRA_ERRORS,
                )
            return
        if is_logical_error:
            count += 1
            _consecutive_tool_errors[agent_id] = (tool_name, count)
            # Reset the infra counter on any logical error — environment
            # recovered, or the LLM is now hitting a different problem.
            _consecutive_infra_errors.pop(agent_id, None)
            # Reset gate-block counters on any non-gate tool call — a real
            # tool call between gate refusals means the LLM is making
            # progress and the escape hatch should reset.
            _reset_gate_blocks(agent_id)
            if count >= _MAX_CONSECUTIVE_ERRORS:
                _consecutive_tool_errors.pop(agent_id, None)
                raise ChildAgentCircuitBreakerError(
                    f"Tool '{tool_name}' failed {count} consecutive times — "
                    f"stopping to prevent token waste"
                )
        else:
            # Reset on success
            _consecutive_tool_errors[agent_id] = (tool_name, 0)
            _consecutive_infra_errors.pop(agent_id, None)


def _extract_tool_name(event: RunItemStreamEvent) -> str:
    """Best-effort extraction of tool name from a tool_called event."""
    item = event.item
    raw = getattr(item, "raw_item", None)
    if isinstance(raw, dict):
        return raw.get("name", "") or raw.get("call_id", "unknown")
    # ResponseFunctionToolCall, McpCall, etc. have a .name attribute
    name = getattr(raw, "name", None)
    if name:
        return str(name)
    return "unknown"


# Throttle window: skip duplicate tool_call events from the same agent if
# the last write was within this many ms. The SDK can fire several stream
# events per logical tool call; we don't want to spam the JSONL.
_LAST_COMMS_EVENT_TS: dict[str, float] = {}
_COMMS_THROTTLE_MS = 50

# Gate-block sentinel and the consecutive-refusal threshold for opening
# the escape hatch. The factory's _finish_tool_use_behavior emits strings
# starting with "GATE BLOCKED: <GateName> ..." for each refused scan
# completion. After N consecutive refusals of the same gate we open the
# escape hatch and let finish_scan through (with a warning) so a scan
# doesn't stall forever on an unsatisfiable gate.
_GATE_BLOCK_PREFIX = "GATE BLOCKED:"
_MAX_CONSECUTIVE_GATE_BLOCKS = 3
_consecutive_gate_blocks: dict[str, dict[str, int]] = {}  # agent_id -> {gate -> count}


# ---------------------------------------------------------------------------
# Claimed-finding detector
# ---------------------------------------------------------------------------
# The LLM can pattern-match "Status 200" / "CVE-2025-XXXX vulnerable" in
# preliminary probe output and write "**Major finding!**" in its
# reasoning — without ever calling the file-finding tool. (Real example
# we saw: an LLM claim a "Critical finding" on a CVE based on a
# `100 Continue` header that got read as `200 OK`; the agent never
# invoked create_vulnerability_report and the user had to cancel the
# scan.)
#
# This tracker fires an UNFILED_CLAIM event when a "claimed finding"
# phrase appears in an llm_message but no corresponding
# create_vulnerability_report (or run_scan_pipeline) tool call lands
# within _CLAIM_WINDOW_S seconds. The gate_escape-hatch-style counter
# keeps a single claim from spamming the JSONL if the agent keeps
# repeating itself.

# Phrases that suggest the LLM believes a finding exists. Lowercased
# substring match against the WHOLE text (not just prefixes) so we
# catch both "**Critical finding**" and "Critical findings:" and
# "**CONFIRMED FINDINGS**". Real model style we observed was:
# "Critical findings:" with no leading asterisks, so we accept both.
# Longest phrases first so
# "**critical finding" wins over "**critical".
_CLAIM_PHRASES: tuple[str, ...] = (
    "**critical finding",
    "**major finding",
    "**confirmed finding",
    "**confirmed**",
    "**exploit confirmed",
    "**exploit succeeded",
    "**vulnerability confirmed",
    "**rce confirmed",
    "**auth bypass confirmed",
    "critical finding",
    "major finding",
    "confirmed finding",
    "confirmed findings",
    "exploit confirmed",
    "exploit succeeded",
    "vulnerability confirmed",
    "rce confirmed",
    "auth bypass confirmed",
    "confirmed exploitable",
    "rce achieved",
    "auth bypass achieved",
)

# Tools that file a finding. If one of these fires within
# _CLAIM_WINDOW_S of the claim, the claim is considered filed.
_FINDING_FILE_TOOLS: frozenset[str] = frozenset(
    {
        "create_vulnerability_report",
        "run_scan_pipeline",
    }
)

_CLAIM_WINDOW_S: float = 60.0
# Per-agent state: maps claim_key -> first_seen_monotonic. claim_key is
# a hashable of (normalized_phrase, endpoint_or_url_hint). One entry per
# distinct claim, not one per event — so a "yes I have a finding"
# repeated 5 times in 30s still produces one UNFILED_CLAIM.
_agent_claims: dict[str, dict[str, float]] = {}  # agent_id -> {claim_key -> first_seen}


def _classify_claim(text: str) -> tuple[str, str] | None:
    """If `text` looks like a finding-claim, return (phrase, hint).

    The hint is a small URL/endpoint-ish substring (or '') so distinct
    claims (different CVEs, different endpoints) get separate entries.
    Returns None for ordinary LLM chatter.

    Best-effort: the goal is to catch obvious "the LLM thinks it
    found something" patterns, not to enumerate every phrasing.
    """
    if not text:
        return None
    lower = text.lower()
    phrase = ""
    for p in _CLAIM_PHRASES:
        if p in lower:
            phrase = p
            break
    if not phrase:
        return None
    # Extract a hint: a URL or /path substring if present, else the
    # first 60 chars of the visible text. The hint is what makes the
    # claim_key distinguishable.
    hint = ""
    # First try a URL
    m = re.search(r"https?://[^\s)>\]]+", text)
    if m:
        hint = m.group(0)[:200]
    if not hint:
        # Then a /path/ thing
        m = re.search(r"/[A-Za-z0-9_./\-]{8,200}", text)
        if m:
            hint = m.group(0)[:200]
    if not hint:
        hint = text[:60]
    return phrase, hint


def _claim_key(phrase: str, hint: str) -> str:
    """Hashable key for one distinct claim. Normalized to lowercase."""
    return f"{phrase.lower()}|{hint.lower()}"


def _record_claim(agent_id: str, phrase: str, hint: str, visible: str) -> str | None:
    """Record a finding-claim. Returns the claim_key if this is the
    FIRST time we've seen this claim, else None (so we don't fire the
    UNFILED_CLAIM event more than once per distinct claim).

    The age-of-claim bookkeeping happens elsewhere, in
    _maybe_emit_unfiled_claims(), which is called on every llm_message
    event so a claim that's been pending for a long time gets the
    UNFILED_CLAIM event at the right moment, not at the moment of the
    first claim phrase.
    """
    key = _claim_key(phrase, hint)
    bucket = _agent_claims.setdefault(agent_id, {})
    if key in bucket:
        return None
    bucket[key] = time.monotonic()
    return key


def _clear_claims_for_tool(agent_id: str, tool_name: str) -> int:
    """If `tool_name` is a finding-filing tool, clear all pending
    claims for the agent. Returns how many were cleared. A successful
    filing (or even an attempt) means the claim is no longer 'unfiled'.
    """
    if tool_name not in _FINDING_FILE_TOOLS:
        return 0
    bucket = _agent_claims.pop(agent_id, None)
    return len(bucket) if bucket else 0


def _maybe_emit_unfiled_claims(agent_id: str, run_id: str) -> int:
    """For every claim older than _CLAIM_WINDOW_S for this agent, emit
    an UNFILED_CLAIM event and drop it from the tracker. Returns how
    many were emitted. Idempotent — re-running on the same agent is
    safe because emitted claims are removed from the bucket.
    """
    bucket = _agent_claims.get(agent_id)
    if not bucket:
        return 0
    now = time.monotonic()
    fired: list[str] = []
    for key, first_seen in list(bucket.items()):
        if (now - first_seen) < _CLAIM_WINDOW_S:
            continue
        phrase, hint = key.split("|", 1)
        try:
            write_status(
                run_id,
                "unfiled_claim",
                {
                    "agent_id": agent_id,
                    "phrase": phrase,
                    "hint": hint,
                    "age_s": round(now - first_seen, 1),
                    "claim_window_s": _CLAIM_WINDOW_S,
                },
            )
            fired.append(key)
        except Exception:
            logger.debug("unfiled_claim emit failed", exc_info=True)
    for k in fired:
        bucket.pop(k, None)
    return len(fired)


def _emit_stream_event_to_comms(agent_id: str, event: Any) -> None:
    """Best-effort: forward interesting SDK stream events to comms/status.jsonl.

    Used by the live tailer (prometheus_tail.sh) to render real-time progress.
    Per-agent throttle prevents event floods from drowning the JSONL.
    Never raises — observability is allowed to fail silently.
    """
    run_id = get_active_run()
    if not run_id:
        return
    etype = getattr(event, "name", type(event).__name__)
    # Cheap throttle keyed on (agent, event-type) so the SDK's natural
    # bursts of the same event type don't drown the JSONL, but different
    # event types from the same agent still pass through. (Pure agent_id
    # keying caused a 4-min flat spot in a representative scan when
    # the root agent was reasoning + tool-calling in a tight loop.)
    last = _LAST_COMMS_EVENT_TS.get((agent_id, etype), 0.0)
    now = time.monotonic()
    if (now - last) < (_COMMS_THROTTLE_MS / 1000.0) and etype in {
        "tool_called",
        "tool_output",
        "message_output_created",
    }:
        return
    _LAST_COMMS_EVENT_TS[(agent_id, etype)] = now
    try:
        if etype == "tool_called":
            tool_name = _extract_tool_name(event)
            raw = getattr(event.item, "raw_item", None) or {}
            args = ""
            if isinstance(raw, dict):
                a = raw.get("arguments", "")
                args = (a if isinstance(a, str) else json.dumps(a)) if a else ""
            else:
                a = getattr(raw, "arguments", None)
                if a:
                    args = a if isinstance(a, str) else json.dumps(a)
            write_status(
                run_id,
                "tool_call_stream",
                {
                    "agent_id": agent_id,
                    "tool": tool_name,
                    "args": args,
                },
            )
            # A successful (or even attempted) call to a finding-filing
            # tool clears any pending "agent claims a finding" alert for
            # the same agent. The gate still enforces that the filing
            # actually completes; this is just the comms-side bookkeeping
            # so we don't fire UNFILED_CLAIM after the agent already
            # called the tool.
            if tool_name in _FINDING_FILE_TOOLS:
                _clear_claims_for_tool(agent_id, tool_name)
        elif etype == "tool_output":
            tool_name = _extract_tool_name(event)
            # Comms stream is the *record*, not a display surface. The
            # full output goes in; the tailer (or any consumer) is free
            # to truncate at render time. Truncating at the source hid
            # real evidence before — e.g. a prior scan where the 200
            # OK + 404 Not Found body was cut to "200 OK" and the agent
            # (and operator) pattern-matched to "reachable."
            output = getattr(event.item, "output", "") or ""
            write_status(
                run_id,
                "tool_output",
                {
                    "agent_id": agent_id,
                    "tool": tool_name,
                    "output": str(output),
                },
            )
            # Detect gate-block events and surface them with the gate name
            # + consecutive-refusal count. This is what makes a stuck-on-gate
            # scan visible to the live tailer in real time — before this,
            # you only saw the LLM complaining in its think tags, not the
            # actual gate that's blocking. Counts per (agent, gate) so a
            # one-off gate_block on a different gate doesn't pollute the
            # counter for the stuck one.
            try:
                gate_name = _classify_gate_block(str(output))
                if gate_name is not None:
                    refusal_count = _record_gate_block(agent_id, gate_name)
                    write_status(
                        run_id,
                        "gate_blocked",
                        {
                            "agent_id": agent_id,
                            "tool": tool_name,
                            "gate": gate_name,
                            "consecutive_refusals": refusal_count,
                            "escape_hatch_open": (refusal_count >= _MAX_CONSECUTIVE_GATE_BLOCKS),
                        },
                    )
            except Exception:
                logger.debug("gate_blocked comms emit failed", exc_info=True)
        elif etype == "message_output_created":
            # LLM text response — useful to see the agent's reasoning
            raw = getattr(event.item, "raw_item", None)
            text = _extract_message_text(raw)
            if text:
                visible, thinking = _split_thinking(text)
                if thinking:
                    # Thinking is its own event with the FULL trace, not
                    # a 200-char preview. The comms stream is the record;
                    # the tailer truncates at display time. This way an
                    # AI agent reading the jsonl can see the agent's
                    # full chain of thought, not just the lead sentence.
                    write_status(
                        run_id,
                        "thinking",
                        {
                            "agent_id": agent_id,
                            "model": _infer_model_from_raw(raw),
                            "text": thinking,
                            "visible_chars": len(visible),
                        },
                    )
                if visible:
                    # Same principle: full visible text in the record.
                    # LLM can produce multi-paragraph final answers —
                    # a 200-char cap was hiding real evidence.
                    write_status(
                        run_id,
                        "llm_message",
                        {
                            "agent_id": agent_id,
                            "model": _infer_model_from_raw(raw),
                            "text": visible,
                        },
                    )
                    # Claimed-finding detector. Fires UNFILED_CLAIM if
                    # the LLM uses claim-phrase language ("**Major
                    # finding**", "**Critical finding**", etc.) but no
                    # finding-filing tool lands within
                    # _CLAIM_WINDOW_S. _maybe_emit_unfiled_claims is
                    # called on every llm_message so a claim that was
                    # filed at the 59s mark never gets the alert.
                    try:
                        classified = _classify_claim(visible)
                        if classified:
                            phrase, hint = classified
                            _record_claim(agent_id, phrase, hint, visible)
                        # Always tick the age-checker — claims from
                        # earlier events may have aged out now.
                        _maybe_emit_unfiled_claims(agent_id, run_id)
                    except Exception:
                        logger.debug("unfiled_claim bookkeeping failed", exc_info=True)
    except Exception:
        logger.debug("_emit_stream_event_to_comms failed", exc_info=True)


# ---------------------------------------------------------------------------
# Thinking-trace parsing
# ---------------------------------------------------------------------------
# Different reasoning models wrap their chain-of-thought differently:
#   - DeepSeek R1 / Qwen QwQ / Hermes:     <think>...</think>
#   - OpenAI o-series:                      reasoning item with .summary[].text
#   - Claude (extended_thinking):           thinking blocks with .signature
#   - Gemini thinking:                      inline <think>...</think> in content
#   - TokenRouter MiniMax-M3:               <think>...</think> (DeepSeek-style)
#
# The SDK surfaces all of these as MessageOutputItem with raw_item.content
# being a list of blocks. We:
#   1. Find the first text block with a known think-wrapping tag, split it.
#   2. If no wrapping tag, check for a separate "reasoning" content block.
#   3. Fall back to no split (visible == raw, thinking == '').

_THINK_OPEN_RE = re.compile(r"<think>", re.IGNORECASE)
_THINK_CLOSE_RE = re.compile(r"</think>", re.IGNORECASE)
# Some models (qwen3, hermes thinking) emit raw <think> without a closing tag
# in the streamed chunk; we still want to flag it as thinking.

# Map model-id substrings to a short, human-readable "kind" we surface in
# the tail. Lower-cased substring match — order matters (longest first).
_MODEL_KIND_HINTS: list[tuple[str, str]] = [  # codeql[py/unused-global-variable] : reserved for future tail-renderer short-name mapping; populated below for downstream tooling
    ("minimax", "mimo"),
    ("mimo", "mimo"),
    ("qwq", "qwen-qwq"),
    ("qwen", "qwen"),
    ("o1-mini", "openai-o1"),
    ("o1-preview", "openai-o1"),
    ("o1-", "openai-o1"),
    ("o3-", "openai-o3"),
    ("o4-", "openai-o4"),
    ("gpt-5", "openai-gpt5"),
    ("claude", "anthropic"),
    ("gemini", "gemini"),
    ("hermes", "hermes"),
    ("llama", "llama"),
    ("mistral", "mistral"),
]


def _infer_model_from_raw(raw: Any) -> str:
    """Best-effort: extract a short model identifier from a message raw_item.

    Looks at common attributes (``model``, ``model_id``, ``response.model``)
    and falls back to ''. Used only to label the ``thinking`` event so the
    tailer can show "THINK model=mimo" instead of just "THINK".
    """
    if raw is None:
        return ""
    for attr in ("model", "model_id"):
        v = getattr(raw, attr, None)
        if isinstance(v, str) and v:
            return v[-30:]
    # Look inside nested .response
    response = getattr(raw, "response", None)
    if response is not None:
        v = getattr(response, "model", None)
        if isinstance(v, str) and v:
            return v[-30:]
    return ""


def _extract_message_text(raw: Any) -> str:
    """Pull the visible text out of a raw message item, regardless of how
    the SDK shaped it. Returns '' if nothing useful is found.

    Tries ``raw.content`` as both string and list-of-blocks, then falls
    back to ``raw.text`` / ``raw.message`` for older shapes.
    """
    if raw is None:
        return ""
    for attr in ("content", "text", "message"):
        v = getattr(raw, attr, None)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, list) and v:
            parts: list[str] = []
            for block in v:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    t = block.get("text")
                    if isinstance(t, str):
                        parts.append(t)
                else:
                    t = getattr(block, "text", None)
                    if isinstance(t, str):
                        parts.append(t)
            if parts:
                return "\n".join(parts)
    return ""


def _split_thinking(text: str) -> tuple[str, str]:
    """Return (visible_text, thinking_text) given a model response.

    Handles:
      - ``<think>...</think>`` blocks (DeepSeek, MiniMax-M3, Hermes, QwQ, etc.)
      - Unclosed ``<think>`` at the start (treat entire text as thinking)
      - Claude extended-thinking ``<thinking>...</thinking>`` (rare via SDK)
      - No wrapping tags → returns (text, '')
    """
    if not text:
        return "", ""
    # Try <think>...</think> first (most common)
    m_open = _THINK_OPEN_RE.search(text)
    if m_open:
        m_close = _THINK_CLOSE_RE.search(text, m_open.end())
        if m_close:
            thinking = text[m_open.end() : m_close.start()].strip()
            visible = (text[: m_open.start()] + text[m_close.end() :]).strip()
            return visible, thinking
        # Unclosed <think> — model streamed a chunk that was all thinking.
        # Treat the whole thing as thinking so the tailer still gets it.
        return "", text.strip()
    # Try <thinking>...</thinking> (Anthropic extended thinking, when present
    # in text rather than as a separate block — rare but worth a shot).
    anthro_match = re.search(r"<thinking>(.*?)</thinking>", text, re.DOTALL | re.IGNORECASE)
    if anthro_match:
        thinking = anthro_match.group(1).strip()
        visible = (text[: anthro_match.start()] + text[anthro_match.end() :]).strip()
        return visible, thinking
    return text, ""


# --- Per-gate consecutive-block tracker helpers ---
# These were moved to module top so _emit_stream_event_to_comms can
# reference them; the actual functions still live below.
def _classify_gate_block(output: Any) -> str | None:
    """If the tool output starts with the gate-block sentinel, return the
    gate name (the substring between 'GATE BLOCKED:' and the next newline
    or period).  Otherwise return None.

    This is the third error category — distinct from logical errors
    (which count against the circuit breaker) and infra errors (which
    have their own higher threshold). Gate-blocks are the LLM doing the
    right thing; they should not count against any breaker at all, but
    we do want to know if the same gate keeps refusing so we can open
    an escape hatch.
    """
    if not isinstance(output, str):
        return None
    if _GATE_BLOCK_PREFIX not in output:
        return None
    # Extract the gate name from the first line: "GATE BLOCKED: Tor verification ..."
    try:
        after = output.split(_GATE_BLOCK_PREFIX, 1)[1].lstrip()
        first_line = after.split("\n", 1)[0].split(".", 1)[0].strip()
        # First 3-5 words is the gate name (Tor / Fingerprint / Research / etc.)
        return first_line[:60] or "unknown"
    except Exception:
        return "unknown"


def _record_gate_block(agent_id: str, gate_name: str) -> int:
    """Record one gate-block refusal; return the new consecutive count for
    this (agent, gate) pair. Resets other gates' counts (each gate has its
    own escape hatch — fixing one shouldn't mask another's stuck state)."""
    agent_blocks = _consecutive_gate_blocks.setdefault(agent_id, {})
    # If this is a different gate than last time, reset the old counter
    if agent_blocks.get("_last_gate") not in (None, gate_name):
        agent_blocks.clear()
    agent_blocks[gate_name] = agent_blocks.get(gate_name, 0) + 1
    agent_blocks["_last_gate"] = gate_name
    return agent_blocks[gate_name]


def _reset_gate_blocks(agent_id: str) -> None:
    _consecutive_gate_blocks.pop(agent_id, None)


def _is_tool_output_error(output: Any) -> str | None:
    """Classify a tool output as one of:
      - 'logical'  : the tool itself returned an error (LLM's fault, retry needed)
      - 'infra'    : transient environmental failure (sandbox, network, disk)
      - 'gate'     : lifecycle tool returned a gate-block sentinel (LLM is right)
      - None       : success, no error

    Returned as a string so call sites can branch on it; returns None for success.
    Split out from the old bool-returning version to support the new
    three-way classification without changing the existing infra detection.
    """
    if not isinstance(output, str) or not output.strip():
        return None
    # Gate block sentinel takes priority over infra / logical — the agent is
    # following protocol, the gate is the one refusing.
    if _classify_gate_block(output) is not None:
        return "gate"
    # Try JSON parse – only flag top-level "error" key as genuine error
    try:
        parsed = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        pass
    else:
        if isinstance(parsed, dict) and "error" in parsed:
            return "logical"
        # Non-dict JSON (list, string, number) or dict without top-level "error" → not an error
        return None
    # Non-JSON output: look for genuine error indicators
    lowered = output.lower()
    if "traceback (most recent call last)" in lowered:
        return "logical"
    if re.search(r"process exited with code\s+[1-9]", lowered):
        return "logical"
    for prefix in ("error:", "tool error:", "execution failed:", "failed:"):
        if lowered.startswith(prefix):
            return "logical"
    if re.search(r"\berror\b", lowered):
        return "logical"
    return None


# Internal alias for the str-returning implementation. Set BEFORE the
# bool-returning shim rebinds the public name below, so the alias always
# references the original tri-state function (no recursion).
_is_tool_output_error_kind = _is_tool_output_error


# Backwards-compat shim: the old bool-returner is still imported by the
# historic test suite. Map None / non-error to False, anything else to True.
def _is_tool_output_error_bool(output: Any) -> bool:
    return _is_tool_output_error_kind(output) is not None


# Phase 2B: keep the deprecated `_is_tool_output_error` returning a
# bool when the historic test suite expected booleans. Re-export the
# boolean-returning version under the historic name so the existing
# test imports keep working. The str-returning version remains primary
# (call sites that want the kind use it).
_is_tool_output_error = _is_tool_output_error_bool  # type: ignore[assignment]  # codeql[py/unused-global-variable] : kept as a re-export of the bool-returning shim for tests/test_circuit_breaker.py  # codeql[py/unused-global-variable] : historical boolean re-export retained for tests/test_circuit_breaker.py


# Infrastructure-level failures that should NOT trip the consecutive-tool-error
# circuit breaker. These are transient environmental issues (disk full, network
# down, Docker daemon stuck) where the LLM has done nothing wrong — it just
# retried the same valid command. The right response is to back off, not to
# kill the agent after 10 retries and waste the entire scan.
_INFRA_ERROR_PATTERNS: tuple[str, ...] = (
    # Disk / filesystem
    "no space left on device",
    "disk quota exceeded",
    "structure needs cleaning",
    "read-only file system",
    "input/output error",
    # Network / transport
    "connection refused",
    "connection reset",
    "connection timed out",
    "connection aborted",
    "network is unreachable",
    "no route to host",
    "name resolution failed",
    "temporary failure in name resolution",
    "tls handshake timeout",
    "ssl: certificate verify failed",
    "connection closed by peer",
    # Docker / sandbox
    "cannot create .*\\.pid:",
    "cannot create .*\\.sock:",
    "no such container",
    "container is restarting",
    "daemon: not running",
    "docker.sock: connect:",
    # Out-of-memory
    "out of memory",
    "cannot allocate memory",
    # Process / signal transient
    "resource temporarily unavailable",
)


def _is_infrastructure_error(output: Any) -> bool:
    """True if the tool output indicates a transient environment failure
    rather than a logical / API error from the tool itself.

    A logical error ("404 Not Found", "invalid input") is the LLM's fault
    or the target's response — the LLM should change strategy. An
    infrastructure error ("No space left on device") is the sandbox's
    fault — the same command will likely succeed once the environment
    recovers, so we should back off and retry, not kill the agent.
    """
    if not isinstance(output, str):
        return False
    lowered = output.lower()
    return any(re.search(pat, lowered) for pat in _INFRA_ERROR_PATTERNS)


# Short, operator-readable category for each infra-error pattern.  Used in
# the periodic warning and the circuit-break error message.
_INFRA_ERROR_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("no space left on device", "ENOSPC"),
    ("disk quota exceeded", "ENOSPC"),
    ("structure needs cleaning", "ENOSPC"),
    ("read-only file system", "ENOSPC"),
    ("input/output error", "EIO"),
    ("connection refused", "ECONNREFUSED"),
    ("connection reset", "ECONNRESET"),
    ("connection timed out", "ETIMEDOUT"),
    ("connection aborted", "ECONNABORTED"),
    ("network is unreachable", "ENETUNREACH"),
    ("no route to host", "EHOSTUNREACH"),
    ("name resolution failed", "DNS"),
    ("temporary failure in name resolution", "DNS"),
    ("tls handshake timeout", "TLS"),
    ("ssl: certificate verify failed", "TLS"),
    ("connection closed by peer", "ECONNRESET"),
    ("cannot create .*\\.pid:", "sandbox-pidfile"),
    ("cannot create .*\\.sock:", "sandbox-sock"),
    ("no such container", "docker"),
    ("container is restarting", "docker"),
    ("daemon: not running", "docker"),
    ("docker.sock: connect:", "docker"),
    ("out of memory", "OOM"),
    ("cannot allocate memory", "OOM"),
    ("resource temporarily unavailable", "EAGAIN"),
)


def _classify_infra_error(output: Any) -> str:
    """Return a short, stable category for an infrastructure error so the
    operator can grep the scan log. Falls back to 'infrastructure' when
    no specific pattern matches.
    """
    if not isinstance(output, str):
        return "infrastructure"
    lowered = output.lower()
    for pat, category in _INFRA_ERROR_CATEGORIES:
        if re.search(pat, lowered):
            return category
    return "infrastructure"


async def _estimate_session_tokens(session: Session | None) -> int:
    """Rough token estimate from session items. ~4 chars per token."""
    if session is None:
        return 0
    try:
        items = await session.get_items()
    except Exception:
        return 0
    total_chars = 0
    for item in items:
        if isinstance(item, dict):
            total_chars += len(str(item.get("output", "")))
            total_chars += len(str(item.get("content", "")))
    return total_chars // 4


async def _force_session_compaction(
    session: Session | None,
    agent_id: str,
    *,
    keep_recent: int = _CONTEXT_COMPACT_KEEP_RECENT,
) -> int:
    """Drop old tool-output items from the session to free context budget.

    Keeps the most recent *keep_recent* items plus any non-output items
    (system messages, function calls). Returns number of items dropped.
    """
    if session is None:
        return 0
    try:
        items = await session.get_items()
    except Exception:
        return 0

    if len(items) <= keep_recent:
        return 0

    # Identify items to keep: last N items + system/function_call items
    keep_indices: set[int] = set(range(len(items) - keep_recent, len(items)))
    for i, item in enumerate(items):
        if isinstance(item, dict):
            t = item.get("type", "")
            if t in ("message", "function_call"):
                keep_indices.add(i)

    to_drop = [i for i in range(len(items)) if i not in keep_indices]
    if not to_drop:
        return 0

    # Clear and re-add kept items
    await session.clear_session()
    kept = [item for i, item in enumerate(items) if i in keep_indices]
    if kept:
        await session.add_items(kept)

    logger.warning(
        "[agent %s] Forced compaction: %d → %d items (context budget)",
        agent_id,
        len(items),
        len(kept),
    )
    return len(to_drop)


async def _session_has_content(session: Session | None) -> bool:
    """Return True when the session holds at least one real message item.

    Used by the empty-input fail-fast check to avoid 3 doomed LLM
    cycles when both the caller's input_data and the persisted session
    have been emptied (typically by a compaction that was too
    aggressive). When both are empty, no SDK call can succeed.
    """
    if session is None:
        return False
    try:
        items = await session.get_items()
    except Exception:
        # If we cannot read the session, assume it has content — better
        # to attempt the LLM call and let the SDK surface a real error
        # than to fail-fast on a transient read.
        return True
    return bool(items)


class EmptyModelInputError(AgentsException):
    """Raised when the prepared model input is empty AND the session is also
    empty. The OpenAI Agents SDK raises 'Prepared model input is empty'
    in this case; we surface a more actionable error and stop the agent
    immediately so a 5-minute death loop doesn't waste the scan.
    """


async def _run_cycle(  # noqa: PLR0912
    agent: Any,
    coordinator: AgentCoordinator,
    agent_id: str,
    *,
    input_data: Any,
    run_config: RunConfig,
    context: dict[str, Any],
    max_turns: int,
    session: Session | None,
    interactive: bool,
    event_sink: StreamEventSink | None,
    hooks: RunHooks[dict[str, Any]] | None,
) -> RunResultBase | None:
    image_strips = 0
    stream = None
    while True:
        try:
            await coordinator.mark_running(agent_id)
            _cycle_start = time.monotonic()

            # --- Context budget check: prevent context window exhaustion ---
            estimated = await _estimate_session_tokens(session)
            if estimated > _CONTEXT_BUDGET_TOKENS:
                logger.warning(
                    "[agent %s] Context at ~%d tokens (budget=%d), forcing compaction",
                    agent_id,
                    estimated,
                    _CONTEXT_BUDGET_TOKENS,
                )
                dropped = await _force_session_compaction(session, agent_id)
                # After compaction, clear input_data so the agent gets a
                # fresh continuation rather than replaying stale instructions
                if dropped > 0:
                    input_data = []
                logger.info(
                    "[agent %s] Compaction complete: dropped %d items",
                    agent_id,
                    dropped,
                )

            # --- Empty-input fail-fast ---
            # If the caller's input is empty AND the session is also
            # empty (e.g. compaction dropped everything), the SDK will
            # raise "Prepared model input is empty" no matter what we
            # pass. Surface a clear error immediately instead of burning
            # 3 LLM cycles in a retry loop.
            if not input_data and not await _session_has_content(session):
                raise EmptyModelInputError(
                    f"agent {agent_id}: prepared model input is empty and "
                    f"session has no items — compaction or truncation "
                    f"removed all context. Stopping instead of looping."
                )

            logger.info(
                "[agent %s] Starting run_streamed (input_len=%d, max_turns=%d)",
                agent_id,
                len(str(input_data)),
                max_turns,
            )
            stream = Runner.run_streamed(
                agent,
                input=input_data,
                run_config=run_config,
                context=context,
                max_turns=max_turns,
                session=session,
                hooks=hooks,
            )
            logger.info("[agent %s] run_streamed returned, attaching stream", agent_id)
            await coordinator.attach_stream(agent_id, stream)
            try:
                _first_event = True
                loop = asyncio.get_event_loop()
                # Fix 5: wrap stream_events with a per-event stall timeout.
                # If no event arrives within _STREAM_STALL_TIMEOUT seconds the
                # LLM connection is dead (CLOSE-WAIT).  reschedule() resets
                # the deadline on every event so busy scans never time out.
                async with asyncio.timeout(_STREAM_STALL_TIMEOUT) as _stall:
                    async for event in stream.stream_events():
                        _stall.reschedule(loop.time() + _STREAM_STALL_TIMEOUT)
                        if _first_event:
                            _first_event = False
                            _elapsed = time.monotonic() - _cycle_start
                            logger.info(
                                "[agent %s] First stream event after %.1fs",
                                agent_id,
                                _elapsed,
                            )
                        # --- Circuit breaker: track consecutive same-tool errors ---
                        if context.get("parent_id") is not None and isinstance(
                            event, RunItemStreamEvent
                        ):
                            _check_consecutive_tool_errors(agent_id, event)
                        # --- Live observability: emit LLM + tool events to comms ---
                        # The tailer (prometheus_tail.sh) reads these to show what
                        # each agent is doing in real time. Cheap, best-effort.
                        _emit_stream_event_to_comms(agent_id, event)
                        # --- Fix 7: track agent activity for stall detection ---
                        _update_agent_activity(agent_id)
                        # --- Fix 7+8: track tool outputs for progress & WAF detection ---
                        if isinstance(event, RunItemStreamEvent) and event.name == "tool_output":
                            tool_output = getattr(event.item, "output", "")
                            tool_name = _extract_tool_name(event)
                            if isinstance(tool_output, str) and tool_output:
                                _record_progress(agent_id, tool_name, tool_output)
                                if _detect_waf_block(agent_id, tool_output):
                                    logger.warning(
                                        "[agent %s] WAF blocking detected (%d consecutive 403s)",
                                        agent_id,
                                        _agent_consecutive_403s.get(agent_id, 0),
                                    )
                        if event_sink is not None and _check_event_sink_health(agent_id):
                            try:
                                event_sink(agent_id, event)
                            except Exception:
                                logger.exception("stream event sink failed for %s", agent_id)
                                _mark_sink_dead(agent_id)
                if stream.run_loop_exception is not None:
                    raise stream.run_loop_exception
            finally:
                await coordinator.detach_stream(agent_id, stream)
        except Exception as exc:
            if (
                image_strips < 3
                and session is not None
                and getattr(exc, "status_code", None) in _INPUT_REJECTION_CODES
            ):
                try:
                    stripped = await strip_latest_image_from_session(session)
                except Exception:
                    logger.exception("image-strip recovery failed for %s", agent_id)
                    stripped = False
                if stripped:
                    image_strips += 1
                    logger.info(
                        "Stripped latest image from %s session after rejection; retrying (%d)",
                        agent_id,
                        image_strips,
                    )
                    input_data = []
                    continue
            # Fix 4: retry on transport errors (mid-stream connection drops)
            # Works for ALL agents (root + child) since these are transient network issues.
            if isinstance(exc, _TRANSPORT_ERROR_TYPES):
                # Fix 5: cancel the stream on stall timeout to kill the stuck
                # background LLM task (prevents task/connection leaks).
                if isinstance(exc, TimeoutError) and stream is not None:
                    try:
                        stream.cancel()
                    except Exception:
                        logger.debug(
                            "[agent %s] stream.cancel() after stall failed", agent_id, exc_info=True
                        )
                retries = _transport_error_retries.get(agent_id, 0)
                if retries < _TRANSPORT_ERROR_MAX_RETRIES:
                    _transport_error_retries[agent_id] = retries + 1
                    delay = _TRANSPORT_ERROR_BASE_DELAY * (2**retries)
                    logger.warning(
                        "Transport error for %s; retry %d/%d after %.1fs: %s",
                        agent_id,
                        retries + 1,
                        _TRANSPORT_ERROR_MAX_RETRIES,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                # retries exhausted — clean up and fall through
                _transport_error_retries.pop(agent_id, None)

            # Fix 6: retry on provider (API) errors for ALL agents (root + child)
            # Previously only child agents retried; root agents failed immediately.
            # This makes scans self-healing against transient API failures.
            if isinstance(exc, APIError):
                retries = _provider_error_retries.get(agent_id, 0)
                if retries < _PROVIDER_ERROR_MAX_RETRIES:
                    _provider_error_retries[agent_id] = retries + 1
                    delay = _PROVIDER_ERROR_BASE_DELAY * (2**retries)
                    logger.warning(
                        "Provider error for %s; retry %d/%d after %.1fs: %s",
                        agent_id,
                        retries + 1,
                        _PROVIDER_ERROR_MAX_RETRIES,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                # retries exhausted — clean up and fall through
                _provider_error_retries.pop(agent_id, None)
                _provider_error_exhausted.add(agent_id)

            if not interactive:
                # Fix 3: for child agents, retry on provider (API) errors
                # before propagating the exception.
                if (
                    agent_id not in _provider_error_exhausted
                    and isinstance(exc, APIError)
                    and context.get("parent_id") is not None
                ):
                    retries = _provider_error_retries.get(agent_id, 0)
                    if retries < _PROVIDER_ERROR_MAX_RETRIES:
                        _provider_error_retries[agent_id] = retries + 1
                        delay = _PROVIDER_ERROR_BASE_DELAY * (2**retries)
                        logger.warning(
                            "Provider error for child %s; retry %d/%d after %.1fs: %s",
                            agent_id,
                            retries + 1,
                            _PROVIDER_ERROR_MAX_RETRIES,
                            delay,
                            exc,
                        )
                        await asyncio.sleep(delay)
                        continue
                    # retries exhausted — clean up and fall through
                    _provider_error_retries.pop(agent_id, None)
                if isinstance(exc, MaxTurnsExceeded | ChildAgentCircuitBreakerError):
                    status = "stopped"
                    logger.info("Child agent %s stopped: %s", agent_id, type(exc).__name__)
                    if coordinator:
                        await coordinator.set_status(agent_id, status)
                    _consecutive_tool_errors.pop(agent_id, None)
                    _consecutive_infra_errors.pop(agent_id, None)
                    await _notify_parent_on_terminal(coordinator, agent_id, status)
                    return None
                raise
            # Fix 3: for interactive child agents, retry on provider errors
            # before parking as failed.
            if (
                agent_id not in _provider_error_exhausted
                and isinstance(exc, APIError)
                and context.get("parent_id") is not None
            ):
                retries = _provider_error_retries.get(agent_id, 0)
                if retries < _PROVIDER_ERROR_MAX_RETRIES:
                    _provider_error_retries[agent_id] = retries + 1
                    delay = _PROVIDER_ERROR_BASE_DELAY * (2**retries)
                    logger.warning(
                        "Provider error for child %s; retry %d/%d after %.1fs: %s",
                        agent_id,
                        retries + 1,
                        _PROVIDER_ERROR_MAX_RETRIES,
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                # retries exhausted — clean up and fall through
                _provider_error_retries.pop(agent_id, None)
            if isinstance(
                exc, MaxTurnsExceeded | ChildAgentCircuitBreakerError | EmptyModelInputError
            ):
                status: Status = "stopped"
            elif isinstance(exc, RuntimeError) and "Prepared model input is empty" in str(exc):
                # SDK edge case: model input filter produced empty input
                # even though we passed non-empty input_data (or session
                # had content). This is rare with the pre-check above;
                # try ONE retry with cleared input so the SDK can rebuild
                # from session, then give up immediately.
                retries = _empty_input_retries.get(agent_id, 0)
                if retries < 1:
                    _empty_input_retries[agent_id] = retries + 1
                    logger.warning(
                        "[agent %s] Prepared model input is empty (SDK edge case) — "
                        "one retry after %.1fs",
                        agent_id,
                        _EMPTY_INPUT_RETRY_DELAY,
                    )
                    await asyncio.sleep(_EMPTY_INPUT_RETRY_DELAY)
                    input_data = []
                    continue
                # One retry failed — fail fast to avoid 5-min death loop
                _empty_input_retries.pop(agent_id, None)
                logger.warning(
                    "[agent %s] Prepared model input is empty — SDK retry "
                    "exhausted, parking as stopped",
                    agent_id,
                )
                status = "stopped"
            elif isinstance(exc, UserError | AgentsException | APIError):
                status = "failed"
            else:
                status = "crashed"
            # Save progress snapshots to agent metadata for potential respawn
            if status in {"crashed", "failed"}:
                snapshots = _agent_progress_snapshots.get(agent_id, [])
                if snapshots:
                    try:
                        async with coordinator._lock:
                            if agent_id not in coordinator.metadata:
                                coordinator.metadata[agent_id] = {}
                            coordinator.metadata[agent_id]["_progress_snapshots"] = snapshots
                    except Exception:
                        logger.debug(
                            "Failed to save progress snapshots for %s",
                            agent_id,
                        )
                logger.warning(
                    "[crash_handler] Agent %s exception type=%s msg=%s; "
                    "saved %d progress snapshots to metadata",
                    agent_id,
                    type(exc).__name__,
                    str(exc)[:300],
                    len(snapshots),
                )
            logger.exception("agent run failed for %s; parking as %s", agent_id, status)
            await coordinator.set_status(agent_id, status)
            _consecutive_tool_errors.pop(agent_id, None)  # clear circuit breaker state
            _consecutive_infra_errors.pop(agent_id, None)
            await _notify_parent_on_terminal(coordinator, agent_id, status)
            # Attempt immediate auto-respawn for child agents
            if context.get("parent_id") is not None and status in {"failed", "crashed"}:
                try:
                    await auto_respawn_child(coordinator, agent_id, context)
                except Exception:
                    logger.debug(
                        "[crash_handler] auto_respawn_child failed for %s",
                        agent_id,
                        exc_info=True,
                    )
            if context.get("parent_id") is None and status in {"failed", "crashed"}:
                raise
            return None
        else:
            _provider_error_retries.pop(agent_id, None)  # clear retries on success
            _provider_error_exhausted.discard(agent_id)
            _transport_error_retries.pop(agent_id, None)  # clear transport retries on success
            _consecutive_tool_errors.pop(agent_id, None)  # clear circuit breaker state
            _consecutive_infra_errors.pop(agent_id, None)
            await _settle_run_result(coordinator, agent_id, interactive, stream)
            return stream


async def _settle_run_result(
    coordinator: AgentCoordinator,
    agent_id: str,
    interactive: bool,
    stream: Any = None,
) -> None:
    async with coordinator._lock:
        current_status = coordinator.statuses.get(agent_id)

    if current_status != "running":
        return

    # Non-interactive mode: set completed if the SDK returned final_output
    if not interactive:
        if stream is not None and getattr(stream, "final_output", None) is not None:
            await coordinator.set_status(agent_id, "completed")
            logger.debug("agent %s: non-interactive run completed with final_output", agent_id)
        return

    # Interactive mode: if the SDK returned a final_output, the agent called
    # agent_finish.  Don't park as "waiting" — that would let the health monitor
    # restart it with empty input, triggering wasteful LLM calls.
    if stream is not None and getattr(stream, "final_output", None) is not None:
        await coordinator.set_status(agent_id, "completed")
        logger.debug("agent %s: interactive run completed with final_output", agent_id)
        return

    await coordinator.set_status(agent_id, "waiting")


async def _agent_status(coordinator: AgentCoordinator, agent_id: str) -> Status | None:
    async with coordinator._lock:
        return coordinator.statuses.get(agent_id)


def _final_output_preview(result: RunResultBase | None) -> str:
    final_output = getattr(result, "final_output", None)
    if final_output is None:
        return "<none>"
    text = str(final_output).replace("\n", " ").strip()
    if not text:
        return "<empty>"
    return text[:300]


async def _append_noninteractive_tool_required_message(
    *,
    session: Session | None,
    context: dict[str, Any],
    attempt: int,
    limit: int,
) -> list[dict[str, str]]:
    finish_tool = "finish_scan" if context.get("parent_id") is None else "agent_finish"
    message = (
        "Your previous response ended the autonomous prometheus run without a lifecycle tool call. "
        "That is invalid in non-interactive mode; plain text final answers are ignored. "
        "Continue immediately and call exactly one tool. "
        f"If your work is complete, call {finish_tool}. "
        "If you are blocked waiting for another agent, call wait_for_message. "
        "Otherwise use the appropriate execution or planning tool. "
        f"This is recovery attempt {attempt}/{limit}."
    )
    item = {"role": "user", "content": message}
    if session is None:
        return [item]

    await session.add_items([cast("TResponseInputItem", item)])
    return []


async def _notify_parent_on_terminal(
    coordinator: AgentCoordinator,
    agent_id: str,
    status: str,
) -> None:
    """Notify parent when a child agent reaches any terminal status."""
    if status not in ("crashed", "stopped", "failed", "completed"):
        return
    async with coordinator._lock:
        parent = coordinator.parent_of.get(agent_id)
        name = coordinator.names.get(agent_id, agent_id)
    if parent is None:
        return
    msg_type = "crash" if status == "crashed" else "completion"
    if status == "crashed":
        content = (
            f"[Agent crash] {name} ({agent_id}) terminated unexpectedly. "
            "Stop waiting on this child unless you want to message it again."
        )
    elif status == "stopped":
        content = (
            f"[Agent stopped] {name} ({agent_id}) hit a turn/circuit limit and was stopped. "
            "It did NOT call agent_finish. Check its output above or message it to resume. "
            "Do NOT keep waiting — it will not send a completion message."
        )
    elif status == "completed":
        content = (
            f"[Agent completed] {name} ({agent_id}) finished successfully. "
            "No further action needed for this agent."
        )
    else:  # failed
        content = (
            f"[Agent failed] {name} ({agent_id}) failed with an error. "
            "Stop waiting on this child unless you want to message it again."
        )
    await coordinator.send(
        parent,
        {
            "from": agent_id,
            "type": msg_type,
            "priority": "high",
            "content": content,
        },
    )


async def _start_child_runner(
    *,
    parent_ctx: dict[str, Any],
    coordinator: AgentCoordinator,
    agents_db_path: Path,
    sessions_to_close: list[SQLiteSession],
    run_config: RunConfig,
    max_turns: int,
    interactive: bool,
    child_agent: Any,
    child_id: str,
    name: str,
    parent_id: str | None,
    task: str,
    initial_input: Any,
    start_parked: bool = False,
    event_sink: StreamEventSink | None = None,
    hooks: RunHooks[dict[str, Any]] | None = None,
) -> None:
    logger.debug(
        "_start_child_runner: child=%s (%s) parent=%s task_len=%d parked=%s",
        child_id,
        name,
        parent_id,
        len(task),
        start_parked,
    )
    session = open_agent_session(child_id, agents_db_path)
    # Phase 0+1: Wrap child session with context management
    managed_session = create_context_managed_session(
        inner=session,
        enable_truncation=True,
        enable_masking=True,
        mask_after_turns=3,
    )
    sessions_to_close.append(session)
    await coordinator.attach_runtime(child_id, session=managed_session)

    # --- Child-agent max_turns guard ---
    # Child agents are spawned in a "first attempt" mindset and should
    # not silently inherit an unbounded max_turns from the parent —
    # a runaway child can burn through the parent's budget before the
    # parent gets a chance to react. We cap at _MAX_CHILD_TURNS by
    # default, but honour an explicit override via the env var
    # PROMETHEUS_CHILD_MAX_TURNS so operators can dial it per-program.
    #
    # The old behaviour capped silently and only logged a WARNING;
    # the new behaviour:
    #   1. Logs at INFO (visible in normal log level)
    #   2. Records the cap in the child agent's metadata so the
    #      parent's auto-respawn can see "previous child hit cap"
    #   3. Surfaces the actual requested vs. granted value in the log
    child_cap = _resolve_child_max_turns()
    if max_turns > child_cap:
        logger.info(
            "Capping max_turns for child %s (%s) from %d to %d "
            "(override via PROMETHEUS_CHILD_MAX_TURNS env var; "
            "default cap=%d)",
            child_id,
            name,
            max_turns,
            child_cap,
            _MAX_CHILD_TURNS,
        )
        max_turns = child_cap

    child_ctx: dict[str, Any] = dict(parent_ctx)
    child_ctx["agent_id"] = child_id
    child_ctx["parent_id"] = parent_id
    child_ctx["task"] = task

    task_handle = asyncio.create_task(
        run_agent_loop(
            agent=child_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=child_ctx,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=child_id,
            interactive=interactive,
            session=session,
            start_parked=start_parked,
            event_sink=event_sink,
            hooks=hooks,
        ),
        name=f"agent-{name}-{child_id}",
    )
    await coordinator.attach_runtime(child_id, task=task_handle)
