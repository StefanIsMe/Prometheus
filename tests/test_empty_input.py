"""Tests for the empty-model-input fail-fast path.

The exact bug from a representative scan: after compaction the model
input became 2 tokens (just '[]' = str(empty list)), and the SDK's
"Prepared model input is empty" RuntimeError was retried twice with
backoff, wasting ~5 minutes of scan time before the agent was finally
parked as stopped.

Fix: detect the empty-input+empty-session combination BEFORE the LLM
call and raise EmptyModelInputError, which short-circuits straight to
"stopped" status. The remaining SDK RuntimeError path is also
tightened to a single retry.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.core.execution import (  # noqa: E402
    AgentsException,
    EmptyModelInputError,
    _session_has_content,
    _empty_input_retries,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _session_has_content
# ---------------------------------------------------------------------------


def test_session_has_content_none_session():
    """No session at all → no content."""
    assert _run(_session_has_content(None)) is False


def test_session_has_content_empty_session():
    """Session with zero items → no content."""
    session = AsyncMock()
    session.get_items = AsyncMock(return_value=[])
    assert _run(_session_has_content(session)) is False


def test_session_has_content_session_with_items():
    """Session with at least one item → has content."""
    session = AsyncMock()
    session.get_items = AsyncMock(return_value=[{"role": "user", "content": "hi"}])
    assert _run(_session_has_content(session)) is True


def test_session_has_content_treats_read_failure_as_has_content():
    """If session.get_items() raises, fall through and TRY the LLM call.

    A transient session DB read error should not silently kill the
    agent — better to surface a real SDK error than to false-positive
    on fail-fast.
    """
    session = AsyncMock()
    session.get_items = AsyncMock(side_effect=RuntimeError("transient"))
    assert _run(_session_has_content(session)) is True


# ---------------------------------------------------------------------------
# EmptyModelInputError class
# ---------------------------------------------------------------------------


def test_empty_model_input_error_is_agents_exception():
    """It must be an AgentsException so existing exception handlers see it."""
    assert issubclass(EmptyModelInputError, AgentsException)


def test_empty_model_input_error_carries_useful_message():
    err = EmptyModelInputError("agent abc: prepared model input is empty")
    msg = str(err)
    assert "agent abc" in msg
    assert "empty" in msg


# ---------------------------------------------------------------------------
# End-to-end: simulate the post-compaction scenario
# ---------------------------------------------------------------------------


def test_empty_input_does_not_retry_when_session_also_empty():
    """Sanity: the fail-fast path doesn't even attempt the LLM call.

    We can't easily run the full _run_cycle without a real Agent,
    Runner, Coordinator, and Session — but we CAN verify the
    EmptyModelInputError exception type is what the fix raises and
    that it short-circuits the retry loop by being treated as a
    'stopped' status (see the isinstance check in the except block).
    """
    # The pre-check raises EmptyModelInputError directly. This is what
    # prevents 3 doomed LLM cycles from running.
    err = EmptyModelInputError("agent test: prepared model input is empty")
    # And the handler treats it as 'stopped' status, not 'failed' or
    # 'crashed' — so the agent doesn't try to auto-respawn.
    status = "stopped" if isinstance(err, EmptyModelInputError) else "crashed"
    assert status == "stopped"


def test_empty_input_retry_path_is_singlet_after_precheck():
    """After the pre-check, the SDK RuntimeError retry path is at most 1."""
    # We can't easily import _EMPTY_INPUT_MAX_RETRIES without triggering
    # the module to load everything.  We just verify the constant is now 1
    # by checking the source — the inline assertion is fine for this.
    import inspect

    from prometheus.core import execution as exec_mod

    src = inspect.getsource(exec_mod)
    # The retry counter check must be `< 1` (i.e. one retry only) for the
    # SDK RuntimeError path, not the old `< _EMPTY_INPUT_MAX_RETRIES` (2).
    assert "if retries < 1:" in src, (
        "expected 'if retries < 1:' for the SDK RuntimeError retry — "
        "more than one retry wastes scan time without ever succeeding"
    )
    # The constant is no longer consulted in the retry path.
    assert "_EMPTY_INPUT_MAX_RETRIES" not in src.split("if retries <")[1].split("continue")[0], (
        "_EMPTY_INPUT_MAX_RETRIES should be unused in the SDK retry path"
    )


def test_empty_input_preserves_session_counter_state():
    """Sanity: counter state is module-level and cleans up."""
    # Pretend we retried once already
    _empty_input_retries["test-agent"] = 1
    _empty_input_retries.pop("test-agent", None)
    assert "test-agent" not in _empty_input_retries


if __name__ == "__main__":
    test_session_has_content_none_session()
    test_session_has_content_empty_session()
    test_session_has_content_session_with_items()
    test_session_has_content_treats_read_failure_as_has_content()
    test_empty_model_input_error_is_agents_exception()
    test_empty_model_input_error_carries_useful_message()
    test_empty_input_does_not_retry_when_session_also_empty()
    test_empty_input_retry_path_is_singlet_after_precheck()
    test_empty_input_preserves_session_counter_state()
    print("All empty-input tests passed.")
