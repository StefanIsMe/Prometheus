"""Tests for the create_todo tool's empty-title tolerance.

Background: a scan failed when the LLM emitted a batch of todos that
included a blank ``{"title": ""}`` item. The old code raised mid-loop,
discarding every todo in the call and forcing the LLM to retry — which
it often did not, because the LLM kept emitting the same shape.

This file asserts that a blank-title item in an otherwise-valid batch
is skipped and reported as a per-item error, while the valid todos in
the same call are still created and persisted.

The agents SDK wraps each tool in a FunctionTool whose body is reached
through ``on_invoke_tool(ctx, json_kwargs_string)``. We drive that
boundary the same way the SDK does so the tests cover the real entry
point, not a parallel async function.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.tools.todo import tools as todo_tools  # noqa: E402


class _FakeCtx:
    """Minimal RunContextWrapper stand-in. The real wrapper exposes
    ``tool_name`` and ``context`` (a dict carrying ``agent_id``)."""

    tool_name = "create_todo"

    def __init__(self, agent_id: str = "test-agent") -> None:
        self.context = {"agent_id": agent_id}


@pytest.fixture(autouse=True)
def _isolated_todo_storage(tmp_path, monkeypatch):
    """Reset the module-level storage + path so tests don't leak state."""
    monkeypatch.setattr(todo_tools, "_todos_storage", {})
    monkeypatch.setattr(todo_tools, "_todos_path", tmp_path / "todos.json")
    yield


def _invoke(ctx, payload):
    """Drive the SDK boundary: on_invoke_tool receives a JSON-encoded
    kwargs dict, not a Python list. This mirrors how the agents SDK
    deserializes the LLM's tool call."""
    raw = json.dumps({"todos": payload}) if not isinstance(payload, str) else payload
    return asyncio.run(todo_tools.create_todo.on_invoke_tool(ctx, raw))


def test_blank_title_is_skipped_valid_todos_persist() -> None:
    """A blank title in a 3-item batch must not abort the call —
    the two valid items still get created and persisted."""
    ctx = _FakeCtx("agent-A")
    payload = [
        {"title": "Probe /admin", "priority": "high"},
        {"title": "   ", "priority": "normal"},  # blank after strip
        {"title": "Check JWT alg=none"},
    ]
    result = json.loads(_invoke(ctx, payload))

    assert result["success"] is False, "blank-title item must mark success=False"
    assert result["created_count"] == 2, f"expected 2 valid creates, got {result['created_count']}"
    created_titles = {c["title"] for c in result["created"]}
    assert created_titles == {"Probe /admin", "Check JWT alg=none"}
    assert len(result["errors"]) == 1
    assert result["errors"][0]["index"] == 1
    assert "non-empty" in result["errors"][0]["error"]
    # The valid items must actually land in the storage dict, not just
    # be echoed in the response.
    stored = todo_tools._todos_storage["agent-A"]
    assert len(stored) == 2
    assert all(t["status"] == "pending" for t in stored.values())


def test_all_blank_returns_no_creates_and_error_list() -> None:
    """If every item has a blank title, the call returns success=False
    with an error per index and creates nothing."""
    ctx = _FakeCtx("agent-B")
    payload = [{"title": ""}, {"title": None}, {"title": "   "}]
    result = json.loads(_invoke(ctx, payload))

    assert result["success"] is False
    assert result["created_count"] == 0
    assert [e["index"] for e in result["errors"]] == [0, 1, 2]
    assert todo_tools._todos_storage["agent-B"] == {}


def test_all_valid_returns_success_with_no_errors() -> None:
    """The success path is unchanged for a clean batch."""
    ctx = _FakeCtx("agent-C")
    payload = [
        {"title": "A"},
        {"title": "B", "priority": "low"},
    ]
    result = json.loads(_invoke(ctx, payload))

    assert result["success"] is True
    assert result["created_count"] == 2
    assert "errors" not in result


def test_empty_list_still_returns_existing_error() -> None:
    """Defensive: an empty ``todos`` list is still rejected up front
    with the same 'Provide a non-empty list' error."""
    ctx = _FakeCtx("agent-D")
    result = json.loads(_invoke(ctx, []))
    assert result["success"] is False
    assert "non-empty list" in result["error"]
