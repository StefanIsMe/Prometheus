"""Per-agent todo tools — mirrored to {state_dir}/todos.json."""

from __future__ import annotations

import json
import logging
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NotRequired, TypedDict, Union

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


VALID_PRIORITIES = ["low", "normal", "high", "critical"]
VALID_STATUSES = ["pending", "in_progress", "done", "cancelled"]

# Phase 4C: synonym map for common LLM-side priority spellings. The audit
# found 6 scans that hit "Invalid priority. Must be one of: low, normal,
# high, critical" because the LLM emitted ``"urgent"``, ``"p0"``, etc.
# We map the most common variants to the canonical values before raising.
_PRIORITY_SYNONYMS: dict[str, str] = {
    "urgent": "high",
    "important": "high",
    "asap": "high",
    "blocker": "high",
    "p0": "critical",
    "sev0": "critical",
    "sev1": "high",
    "sev2": "normal",
    "sev3": "low",
    "p1": "high",
    "p2": "normal",
    "p3": "low",
}

_PRIORITY_RANK = {"critical": 0, "high": 1, "normal": 2, "low": 3}
_STATUS_RANK = {"done": 0, "cancelled": 1, "in_progress": 2, "pending": 3}


class _CreateTodoInput(TypedDict):
    title: str
    description: NotRequired[str]
    priority: NotRequired[str]


class _UpdateTodoInput(TypedDict):
    todo_id: str
    title: NotRequired[str]
    description: NotRequired[str]
    priority: NotRequired[str]
    status: NotRequired[str]


def _todo_sort_key(todo: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _STATUS_RANK.get(todo.get("status", "pending"), 99),
        _PRIORITY_RANK.get(todo.get("priority", "normal"), 99),
        todo.get("created_at", ""),
    )


_todos_storage: dict[str, dict[str, dict[str, Any]]] = {}

_todos_path: Path | None = None
_todos_io_lock = threading.RLock()


def hydrate_todos_from_disk(state_dir: Path) -> None:
    global _todos_path  # noqa: PLW0603
    _todos_path = state_dir / "todos.json"
    with _todos_io_lock:
        _todos_storage.clear()
        if not _todos_path.exists():
            return
        try:
            data = json.loads(_todos_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "todos.json at %s is unreadable; starting with empty todos",
                _todos_path,
            )
            return
        if not isinstance(data, dict):
            return
        loaded = 0
        for aid, by_id in data.items():
            if not isinstance(aid, str) or not isinstance(by_id, dict):
                continue
            cleaned = {
                str(tid): t
                for tid, t in by_id.items()
                if isinstance(tid, str) and isinstance(t, dict)
            }
            if cleaned:
                _todos_storage[aid] = cleaned
                loaded += len(cleaned)
        logger.info(
            "todos hydrated from %s (%d agent(s), %d todo(s))",
            _todos_path,
            len(_todos_storage),
            loaded,
        )


def _persist() -> None:
    path = _todos_path
    if path is None:
        return
    try:
        payload = json.dumps(_todos_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _todos_io_lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("todos persist to %s failed", path)


def _agent_id_from(ctx: RunContextWrapper) -> str:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return str(inner.get("agent_id") or "default")


def _get_agent_todos(agent_id: str) -> dict[str, dict[str, Any]]:
    return _todos_storage.setdefault(agent_id, {})


def _normalize_priority(priority: str | None, default: str = "normal") -> str:
    candidate = (priority or default or "normal").lower().strip()
    # Map common LLM-side synonyms (urgent -> high, p0 -> critical, etc.)
    # so the existing tool surface is robust to small wording differences.
    mapped = _PRIORITY_SYNONYMS.get(candidate, candidate)
    if mapped != candidate:
        logger.info(
            "priority synonym: %r -> %r (audit Phase 4C)",
            priority,
            mapped,
        )
        candidate = mapped
    if candidate not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Must be one of: {', '.join(VALID_PRIORITIES)}")
    return candidate


def _sorted_todos(agent_id: str) -> list[dict[str, Any]]:
    todos_list = [
        {**todo, "todo_id": todo_id} for todo_id, todo in _get_agent_todos(agent_id).items()
    ]
    todos_list.sort(key=_todo_sort_key)
    return todos_list


def get_pending_high_priority_todos(agent_id: str) -> list[dict[str, Any]]:
    """Return a list of non-resolved todos with high or critical priority.

    A todo is considered resolved when its status is ``done`` or
    ``cancelled``.  Everything else (``pending``, ``in_progress``)
    counts as still open.
    """
    _resolved = {"done", "cancelled"}
    agent_todos = _get_agent_todos(agent_id)
    return [
        {**todo, "todo_id": todo_id}
        for todo_id, todo in agent_todos.items()
        if todo.get("status") not in _resolved and todo.get("priority") in ("high", "critical")
    ]


def _apply_single_update(
    agent_todos: dict[str, dict[str, Any]],
    todo_id: str,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
    status: str | None = None,
) -> dict[str, Any] | None:
    if todo_id not in agent_todos:
        return {"todo_id": todo_id, "error": f"Todo with ID '{todo_id}' not found"}
    todo = agent_todos[todo_id]
    if title is not None:
        if not title.strip():
            return {"todo_id": todo_id, "error": "Title cannot be empty"}
        todo["title"] = title.strip()
    if description is not None:
        todo["description"] = description.strip() if description else None
    if priority is not None:
        try:
            todo["priority"] = _normalize_priority(priority, str(todo.get("priority", "normal")))
        except ValueError as exc:
            return {"todo_id": todo_id, "error": str(exc)}
    if status is not None:
        status_candidate = status.lower()
        if status_candidate not in VALID_STATUSES:
            return {
                "todo_id": todo_id,
                "error": f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
            }
        todo["status"] = status_candidate
        todo["completed_at"] = (
            datetime.now(UTC).isoformat() if status_candidate in ("done", "cancelled") else None
        )
    todo["updated_at"] = datetime.now(UTC).isoformat()
    return None


def _coerce_todo_ids(value: Any) -> list[str]:
    """Coerce LLM-supplied ``todo_ids`` into a list of strings.

    The tool signatures below type ``todo_ids`` as ``Union[str, list[str]]``
    so the generated JSON Schema has a top-level ``anyOf`` (required by
    strict providers like DeepSeek — an untyped ``Any`` parameter
    produces a schemaless ``{}`` that DeepSeek rejects with
    "Invalid tool parameters schema : one of `type`, `anyOf`, `$ref`
    field is required", which kills the scan on the first turn).

    The Pydantic schema only declares ``string | array``, so the LLM
    cannot send a dict without the SDK raising a ModelBehaviorError
    before the tool body runs. We still accept a comma-separated string
    or a single string ID, and the dict branch below is kept as a
    defensive fallback for any internal caller that hands us a dict
    directly. Returns an empty list if the value cannot be coerced, so
    the caller surfaces a clear "non-empty list required" error instead
    of a validation crash.
    """
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, (int, float)):
                out.append(str(item))
        return out
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        # If the LLM emitted a JSON-looking dict-as-string, try to parse it
        # (the SDK has already parsed the outer envelope, so anything JSON
        # arriving here is unusual but cheap to handle).
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return [str(k).strip() for k in parsed.keys() if str(k).strip()]
            except json.JSONDecodeError:
                logger.debug(
                    "failed to parse dict-as-string %r, falling through", stripped, exc_info=True
                )
        # Comma-separated string: "abc, def, ghi"
        if "," in stripped:
            return [piece.strip() for piece in stripped.split(",") if piece.strip()]
        return [stripped]
    if isinstance(value, dict):
        # Dict like ``{"ef84db": ""}`` or ``{"ef84db": "done"}`` — treat
        # the keys as the todo IDs. Values are ignored.
        return [str(k).strip() for k in value.keys() if str(k).strip()]
    if isinstance(value, (int, float)):
        return [str(value)]
    return []


def _apply_bulk_status(todo_ids: Any, new_status: str, agent_id: str) -> str:
    """Apply a status change to multiple todos.

    ``todo_ids`` is ``Any`` at the boundary so the SDK lets us see what
    the LLM actually emitted. We coerce it to a list of strings via
    :func:`_coerce_todo_ids`; if the result is empty we return a clear
    error rather than raising.
    """
    todo_ids = _coerce_todo_ids(todo_ids)
    agent_todos = _get_agent_todos(agent_id)
    if not todo_ids:
        return json.dumps(
            {
                "success": False,
                "error": f"Provide a non-empty 'todo_ids' list to mark as {new_status}",
            },
            ensure_ascii=False,
            default=str,
        )
    marked: list[str] = []
    errors: list[dict[str, Any]] = []
    timestamp = datetime.now(UTC).isoformat()
    for tid in todo_ids:
        if tid not in agent_todos:
            errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
            continue
        todo = agent_todos[tid]
        todo["status"] = new_status
        todo["completed_at"] = timestamp if new_status in ("done", "cancelled") else None
        todo["updated_at"] = timestamp
        marked.append(tid)
    if marked:
        _persist()
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "marked": marked,
        "marked_count": len(marked),
        "new_status": new_status,
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def create_todo(ctx: RunContextWrapper, todos: list[_CreateTodoInput]) -> str:
    """Create one or more todos for the current agent.

    Each agent (including subagents) has its own private todo list —
    your todos don't leak to other agents and vice versa.

    Args:
        todos: Array of todo objects. Each object supports:

            - ``title`` (str, required): short actionable title,
              e.g. ``"Test /api/admin for IDOR"``.
            - ``description`` (str, optional): extra context.
            - ``priority`` (str, optional): ``"low"`` / ``"normal"`` /
              ``"high"`` / ``"critical"``. Default ``"normal"``.

            Example: ``[{"title": "Probe /admin", "priority": "high"},
            {"title": "Check JWT alg=none"}]``.
    """
    agent_id = _agent_id_from(ctx)
    logger.debug("create_todo: agent=%s todos_len=%d", agent_id, len(todos) if todos else 0)
    try:
        if not todos:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty list of todos to create"},
                ensure_ascii=False,
                default=str,
            )
        agent_todos = _get_agent_todos(agent_id)
        created: list[dict[str, Any]] = []
        for task in todos:
            title = (task.get("title") or "").strip()
            if not title:
                return json.dumps(
                    {"success": False, "error": "Each todo must include a non-empty 'title'"},
                    ensure_ascii=False,
                    default=str,
                )
            task_priority = _normalize_priority(task.get("priority"))
            todo_id = str(uuid.uuid4())[:6]
            timestamp = datetime.now(UTC).isoformat()
            agent_todos[todo_id] = {
                "title": title,
                "description": (task.get("description") or "").strip() or None,
                "priority": task_priority,
                "status": "pending",
                "created_at": timestamp,
                "updated_at": timestamp,
                "completed_at": None,
            }
            created.append({"todo_id": todo_id, "title": title, "priority": task_priority})
    except (ValueError, TypeError) as e:
        return json.dumps(
            {"success": False, "error": f"Failed to create todo: {e}"},
            ensure_ascii=False,
            default=str,
        )
    _persist()
    logger.debug(
        "create_todo: agent=%s created=%d total=%d",
        agent_id,
        len(created),
        len(_get_agent_todos(agent_id)),
    )
    return json.dumps(
        {
            "success": True,
            "created": created,
            "created_count": len(created),
            "todos": _sorted_todos(agent_id),
            "total_count": len(_get_agent_todos(agent_id)),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_todos(
    ctx: RunContextWrapper,
    status: str | None = None,
    priority: str | None = None,
) -> str:
    """List the current agent's todos, sorted by status then priority.

    Sort order: done -> in_progress -> pending, then critical -> high ->
    normal -> low within each status bucket.

    Args:
        status: Filter by status (``"pending"`` / ``"in_progress"`` / ``"done"``).
        priority: Filter by priority (``"low"`` / ``"normal"`` / ``"high"`` / ``"critical"``).
    """
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        status_filter = status.lower() if isinstance(status, str) else None
        priority_filter = priority.lower() if isinstance(priority, str) else None

        todos_list: list[dict[str, Any]] = []
        for todo_id, todo in agent_todos.items():
            if status_filter and todo.get("status") != status_filter:
                continue
            if priority_filter and todo.get("priority") != priority_filter:
                continue
            entry = todo.copy()
            entry["todo_id"] = todo_id
            todos_list.append(entry)

        todos_list.sort(key=_todo_sort_key)

        summary: dict[str, int] = {"pending": 0, "in_progress": 0, "done": 0, "cancelled": 0}
        for todo in todos_list:
            sv = todo.get("status", "pending")
            summary[sv] = summary.get(sv, 0) + 1
    except (ValueError, TypeError) as e:
        return json.dumps(
            {
                "success": False,
                "error": f"Failed to list todos: {e}",
                "todos": [],
                "filtered_count": 0,
                "total_count": 0,
                "summary": {"pending": 0, "in_progress": 0, "done": 0},
            },
            ensure_ascii=False,
            default=str,
        )

    return json.dumps(
        {
            "success": True,
            "todos": todos_list,
            "filtered_count": len(todos_list),
            "total_count": len(agent_todos),
            "summary": summary,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_todo(ctx: RunContextWrapper, updates: list[_UpdateTodoInput]) -> str:
    """Update one or more todos. Handles all editable fields including status.

    For simple status-only changes you can also use ``mark_todo_completed``
    or ``mark_todo_in_progress``.

    Args:
        updates: Array of update objects. Each object supports:

            - ``todo_id`` (str, required): ID returned by ``create_todo``.
            - ``title`` (str, optional): new title.
            - ``description`` (str, optional): new description (empty clears it).
            - ``priority`` (str, optional): ``"low"`` / ``"normal"`` / ``"high"`` / ``"critical"``.
            - ``status`` (str, optional): ``"pending"`` / ``"in_progress"`` / ``"done"``.

            Omitted fields stay unchanged. Example: ``[{"todo_id": "abc",
            "status": "in_progress", "priority": "high"}]``.
    """
    agent_id = _agent_id_from(ctx)
    try:
        if not updates:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty list of updates"},
                ensure_ascii=False,
                default=str,
            )
        agent_todos = _get_agent_todos(agent_id)
        updated: list[str] = []
        errors: list[dict[str, Any]] = []
        for upd in updates:
            todo_id = upd.get("todo_id", "").strip()
            if not todo_id:
                errors.append({"todo_id": todo_id, "error": "Missing 'todo_id'"})
                continue
            err = _apply_single_update(
                agent_todos,
                todo_id,
                upd.get("title"),
                upd.get("description"),
                upd.get("priority"),
                upd.get("status"),
            )
            if err:
                errors.append(err)
            else:
                updated.append(todo_id)
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    if updated:
        _persist()
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "updated": updated,
        "updated_count": len(updated),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def mark_todo_completed(ctx: RunContextWrapper, todo_ids: str | list[str]) -> str:
    """Mark one or more todos as done (completed).

    Args:
        todo_ids: One or more todo IDs. Accepts a JSON array
            ``["abc123", "def456"]``, a single string ``"abc123"``, or
            a comma-separated string ``"abc123, def456"``. An empty /
            missing value surfaces a clear "non-empty list required"
            error.
    """
    return _apply_bulk_status(todo_ids, "done", _agent_id_from(ctx))


@function_tool(timeout=30)
async def mark_todo_in_progress(ctx: RunContextWrapper, todo_ids: str | list[str]) -> str:
    """Mark one or more todos as in progress.

    Args:
        todo_ids: Same flexible shape as ``mark_todo_completed``.
    """
    return _apply_bulk_status(todo_ids, "in_progress", _agent_id_from(ctx))


@function_tool(timeout=30)
async def delete_todo(ctx: RunContextWrapper, todo_ids: str | list[str]) -> str:
    """Delete one or more todos. Removes them entirely (no soft-delete).

    Args:
        todo_ids: Same flexible shape as ``mark_todo_completed``.
    """
    agent_id = _agent_id_from(ctx)
    todo_ids = _coerce_todo_ids(todo_ids)
    try:
        agent_todos = _get_agent_todos(agent_id)
        if not todo_ids:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'todo_ids' list to delete"},
                ensure_ascii=False,
                default=str,
            )

        deleted: list[str] = []
        errors: list[dict[str, Any]] = []
        for tid in todo_ids:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue
            del agent_todos[tid]
            deleted.append(tid)
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    if deleted:
        _persist()
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "deleted": deleted,
        "deleted_count": len(deleted),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)
