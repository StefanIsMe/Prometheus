"""Tests for the todo tool JSON schemas.

Background: a full scan of app.launchdarkly.com failed on the very
first LLM call with::

    openai.BadRequestError: Error code: 400
    Provider returned error: Invalid tool parameters schema
    : one of `type`, `anyOf`, `$ref` field is required

OpenRouter routed the request to DeepSeek, which strictly validates
JSON Schema. The three bulk-id tools typed ``todo_ids: Any``, so
Pydantic produced a schemaless ``{}`` for the property. DeepSeek
rejected the whole tool list and the scan aborted before any
recon could run.

This file asserts that the bulk-id tool schemas now declare
``Union[str, list[str]]`` (``anyOf: [string, array]``) at the root of
the property so strict providers accept them. It also guards the
``_coerce_todo_ids`` body against the same input shapes it always
handled.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

import pytest  # noqa: E402

from prometheus.tools.todo.tools import (  # noqa: E402
    _coerce_todo_ids,
    delete_todo,
    mark_todo_completed,
    mark_todo_in_progress,
)


# ---------------------------------------------------------------------------
# 1. Schema must declare anyOf at the property root (DeepSeek strict mode)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    [mark_todo_completed, mark_todo_in_progress, delete_todo],
    ids=["mark_todo_completed", "mark_todo_in_progress", "delete_todo"],
)
def test_todo_ids_schema_has_anyof(tool: Any) -> None:
    """DeepSeek rejects schemas whose property has no type/anyOf/$ref.

    Regression for the app.launchdarkly.com scan crash. If this test
    breaks, the bulk-id tools will fail on any provider that routes
    through DeepSeek (or any other strict schema validator).
    """
    schema = tool.params_json_schema
    prop = schema["properties"]["todo_ids"]
    assert "anyOf" in prop, (
        f"{tool.name}: 'todo_ids' must declare anyOf — strict providers "
        f"(DeepSeek, etc.) reject schemaless properties. Got: {prop!r}"
    )
    # And the union must be the shapes the tool body actually accepts.
    variants = prop["anyOf"]
    types = {v.get("type") for v in variants}
    assert "string" in types, f"{tool.name}: anyOf must include 'string'"
    assert "array" in types, f"{tool.name}: anyOf must include 'array'"


# ---------------------------------------------------------------------------
# 2. _coerce_todo_ids still handles the input shapes the tool surface exposes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (["abc123", "def456"], ["abc123", "def456"]),
        (["abc123", 42], ["abc123", "42"]),
        ("abc123", ["abc123"]),
        ("abc123, def456", ["abc123", "def456"]),
        (None, []),
        ("", []),
        ([], []),
    ],
)
def test_coerce_todo_ids_accepts_schema_shapes(raw: Any, expected: list[str]) -> None:
    """The function body must normalise every shape the schema advertises."""
    assert _coerce_todo_ids(raw) == expected


def test_coerce_todo_ids_dict_is_defensive_fallback() -> None:
    """Dicts are no longer reachable through the public schema, but the
    function body keeps the branch in case an internal caller hands one
    in. If this test breaks, the only fallout is a one-line warning, not
    a scan crash — but we still want the fallback to behave sanely.
    """
    assert _coerce_todo_ids({"abc123": "done", "def456": ""}) == [
        "abc123",
        "def456",
    ]


# ---------------------------------------------------------------------------
# 3. Smoke: the three tools still import + instantiate
# ---------------------------------------------------------------------------


def test_all_bulk_tools_present() -> None:
    """A guard so a future rename doesn't silently remove a tool from the
    agent's base list — which would skip a regression in CI but only
    surface as a missing tool in production."""
    for tool in (mark_todo_completed, mark_todo_in_progress, delete_todo):
        assert tool.name, f"{tool!r} has no name"
        assert tool.params_json_schema, f"{tool.name} has no schema"
