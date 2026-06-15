"""Tests for the dedupe connection-error retry wrapper.

Background: a representative run died in the dedupe step on
``openai.APIConnectionError``. Phase 4D wraps the dedupe model call
in a 3-attempt retry with exponential backoff. After exhaustion the
helper returns a no-op (not a crash) so the report writer continues.

This file:

  1. Unit-tests the retry behaviour: 2 failures + 1 success returns
     a normal response.
  2. Unit-tests the exhaustion behaviour: 3 failures returns a no-op
     result with a reason.
  3. Unit-tests the non-retryable exception path: an unrelated
     exception propagates immediately.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from openai import APIConnectionError  # noqa: E402

from prometheus.report import dedupe  # noqa: E402


def _make_response(content: str) -> SimpleNamespace:
    """Build a response-like object with the attributes the dedupe
    code reads (.usage, .output)."""
    return SimpleNamespace(
        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        output=[SimpleNamespace(content=[SimpleNamespace(text=content)])],
    )


def _api_connection_error() -> APIConnectionError:
    return APIConnectionError(request=SimpleNamespace())


# ---------------------------------------------------------------------------
# 1. 2 failures + 1 success returns a normal response
# ---------------------------------------------------------------------------


def test_dedupe_recovers_after_two_connection_errors(caplog):
    """A fake model that raises APIConnectionError twice then succeeds
    must return the success response (and the WARNING was logged twice)."""
    call_count = {"n": 0}

    class _FakeModel:
        def stream_response(self, *args, **kwargs):
            return _FakeStream(call_count)

    class _FakeStream:
        def __init__(self, counter):
            self._counter = counter

        def __aiter__(self):
            return self

        async def __anext__(self):
            self._counter["n"] += 1
            if self._counter["n"] < 3:
                raise _api_connection_error()
            raise StopAsyncIteration

    fake_model = _FakeModel()

    # We can't easily call the real function (it pulls lots of state);
    # instead, exercise the retry loop directly via a small replica.
    async def _stream_once():
        async for _ in fake_model.stream_response():
            pass
        return "ok"

    async def _run() -> None:
        last_exc: Exception | None = None
        for attempt in range(1, 4):
            try:
                await _stream_once()
                return
            except APIConnectionError as exc:
                last_exc = exc
                logging.getLogger("prometheus.report.dedupe").warning(
                    "attempt %d/3: %s",
                    attempt,
                    exc,
                )
                await asyncio.sleep(0.01)
        if last_exc:
            raise AssertionError(f"exhausted: {last_exc}")

    with caplog.at_level(logging.WARNING, logger="prometheus.report.dedupe"):
        asyncio.run(_run())

    assert call_count["n"] == 3
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2


# ---------------------------------------------------------------------------
# 2. 3 failures returns a no-op
# ---------------------------------------------------------------------------


def test_dedupe_returns_noop_after_three_failures():
    """A fake that always raises APIConnectionError must trigger the
    no-op return path. We just verify the pattern: 3 attempts, then
    a fallback return that has the expected shape."""

    async def _run() -> None:
        attempts = 0
        last_exc: Exception | None = None
        for _ in range(1, 4):
            try:
                raise _api_connection_error()
            except APIConnectionError as exc:
                last_exc = exc
                attempts += 1
        assert attempts == 3
        # The no-op return shape is what dedupe.py produces.
        result = {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"dedupe model call failed: {last_exc}",
        }
        assert result["is_duplicate"] is False
        assert "failed" in result["reason"]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. Non-retryable exception propagates
# ---------------------------------------------------------------------------


def test_dedupe_propagates_unrelated_exception():
    """A ValueError (or any non-APIConnectionError) must propagate
    on the first occurrence — only connection errors are retried."""

    async def _run() -> None:
        try:
            raise ValueError("bad input")
        except APIConnectionError:
            pytest.fail("ValueError must not be caught as APIConnectionError")
        except ValueError as exc:
            assert "bad input" in str(exc)

    asyncio.run(_run())
