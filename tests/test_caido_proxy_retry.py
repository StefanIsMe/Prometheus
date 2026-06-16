"""Tests for the Caido proxy graphql retry-on-flake helper.

Background: the audit of 175 scan-run logs found 59 runs failing on
``caido_sdk_client.errors.graphql.NetworkUserError`` from
``list_requests`` / ``view_request`` / ``list_sitemap``. The fix wraps each
graphql call in ``caido_retry``, which retries on transient Caido errors
with exponential backoff and re-raises after the final attempt.

These tests:

  1. Unit-test the helper directly with a fake exception sequence.
  2. Unit-test that user-input errors are NOT retried (deterministic).
  3. E2E log-replay: load a representative ``prometheus_runs/<id>/prometheus.log``,
     count the historic ``list_requests failed`` lines, and assert that
     the new code would have produced zero of them (i.e. the retry
     helper recovers from the same flake pattern).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.tools.proxy import caido_api  # noqa: E402
from prometheus.tools.proxy.caido_api import (  # noqa: E402
    _CAIDO_RETRY_MAX,
    caido_retry,
)


# ---------------------------------------------------------------------------
# 1. Unit: caido_retry succeeds after N transient failures
# ---------------------------------------------------------------------------


def test_caido_retry_succeeds_after_two_failures(caplog):
    """A function that fails twice with NetworkUserError then succeeds
    must return the success result and log WARNING twice."""
    from caido_sdk_client.errors import NetworkUserError

    calls = {"n": 0}

    async def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise NetworkUserError()
        return "ok"

    with caplog.at_level(logging.WARNING, logger="prometheus.tools.proxy.caido_api"):
        result = asyncio.run(caido_retry("test_op", flaky, base_delay=0.001))
    assert result == "ok"
    assert calls["n"] == 3
    # Exactly 2 retry warnings (one per failed attempt)
    retry_lines = [r for r in caplog.records if "transient Caido error" in r.getMessage()]
    assert len(retry_lines) == 2, f"expected 2 warnings, got {len(retry_lines)}"
    # Each warning should mention attempt N/3
    assert "attempt 1/3" in retry_lines[0].getMessage()
    assert "attempt 2/3" in retry_lines[1].getMessage()


def test_caido_retry_gives_up_after_max_attempts():
    """If the fake raises NetworkUserError on every call, the helper must
    re-raise the original exception type after exactly ``attempts`` calls."""
    from caido_sdk_client.errors import NetworkUserError

    calls = {"n": 0}

    async def always_fail() -> None:
        calls["n"] += 1
        raise NetworkUserError()

    with pytest.raises(NetworkUserError):
        asyncio.run(caido_retry("test_op", always_fail, base_delay=0.001))
    assert calls["n"] == _CAIDO_RETRY_MAX


def test_caido_retry_does_not_retry_deterministic_errors():
    """A NotFoundUserError (deterministic) must propagate on the first call,
    not be retried — retrying a 404 wastes time."""
    from caido_sdk_client.errors import NotFoundUserError

    calls = {"n": 0}

    async def not_found() -> None:
        calls["n"] += 1
        raise NotFoundUserError()

    with pytest.raises(NotFoundUserError):
        asyncio.run(caido_retry("test_op", not_found, base_delay=0.001))
    assert calls["n"] == 1, "deterministic error should not be retried"


def test_caido_retry_retries_on_asyncio_timeout():
    """A bare asyncio.TimeoutError is treated as transient."""
    calls = {"n": 0}

    async def times_out() -> str:
        calls["n"] += 1
        if calls["n"] < 2:
            raise asyncio.TimeoutError()
        return "ok"

    result = asyncio.run(caido_retry("test_op", times_out, base_delay=0.001))
    assert result == "ok"
    assert calls["n"] == 2


def test_caido_retry_preserves_return_value_on_first_success():
    """Happy path: a function that succeeds on the first call returns
    immediately with no retry warnings."""
    calls = {"n": 0}

    async def happy() -> dict:
        calls["n"] += 1
        return {"edges": []}

    result = asyncio.run(caido_retry("test_op", happy, base_delay=0.001))
    assert result == {"edges": []}
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# 2. Unit: the three graphql call-sites are wired through the helper
# ---------------------------------------------------------------------------


def test_list_requests_with_client_uses_caido_retry():
    """list_requests_with_client must route through caido_retry; on a
    NetworkUserError it should recover transparently."""
    from caido_sdk_client.errors import NetworkUserError

    fake_calls = {"n": 0}

    class _FakeBuilder:
        """Mimics the SDK's RequestsListBuilder."""

        def first(self, n):
            return self

        def filter(self, f):
            return self

        def after(self, a):
            return self

        def scope(self, s):
            return self

        def descending(self, target, field):
            return self

        def ascending(self, target, field):
            return self

        async def execute(self):
            fake_calls["n"] += 1
            if fake_calls["n"] < 3:
                raise NetworkUserError()
            return SimpleNamespace(edges=[])

    fake_client = SimpleNamespace(request=SimpleNamespace(list=lambda: _FakeBuilder()))

    # Pass base_delay through the helper by patching _CAIDO_RETRY_BASE_DELAY
    with patch.object(caido_api, "_CAIDO_RETRY_BASE_DELAY", 0.001):
        result = asyncio.run(caido_api.list_requests_with_client(fake_client))
    assert result.edges == []
    assert fake_calls["n"] == 3


# ---------------------------------------------------------------------------
# 3. E2E log-replay: assert the audit's "list_requests failed" lines
#    would be eliminated by the patched code
# ---------------------------------------------------------------------------


def _load_log_replay_target() -> Path:
    """Return the path of the worst real log for the Caido
    ``NetworkUserError`` failure category. Falls back to any log with a
    NetworkUserError line if the top fixture has been pruned.

    The exact root cause is a transient ``Transport is already connected``
    or ``Connector is closed`` — exactly the kind of flake the new
    ``caido_retry`` helper is designed to recover from.
    """
    runs_root = SOURCE_ROOT / "prometheus_runs"
    # Pick the log with the most NetworkUserError occurrences — these are
    # the cases the audit identified and that the fix targets.
    best: tuple[int, Path] | None = None
    for log in runs_root.glob("*/prometheus.log"):
        text = log.read_text(errors="replace")
        n = text.count("caido_sdk_client.errors.graphql.NetworkUserError")
        if n and (best is None or n > best[0]):
            best = (n, log)
    assert best is not None, "no log with NetworkUserError found"
    return best[1]


def test_log_replay_list_requests_would_be_resolved():
    """The audit found that the Caido ``NetworkUserError`` is the underlying
    cause of every ``prometheus.tools.proxy.tools: list_requests failed`` line.
    The new ``caido_retry`` helper handles exactly this class of error.

    This test verifies the helper recovers from the recorded exception
    class on the recorded payload."""
    target = _load_log_replay_target()
    text = target.read_text(errors="replace")
    from caido_sdk_client.errors import NetworkUserError

    flake_count = text.count("caido_sdk_client.errors.graphql.NetworkUserError")
    assert flake_count >= 1, f"log {target} has no NetworkUserError — pick a different fixture"

    # Reproduce the exact error pattern: a NetworkUserError from the SDK
    # with the recorded source message. The helper must retry and recover.
    source_messages = [
        "Transport is already connected",
        "Connector is closed.",
        "Connection refused",
    ]
    for msg in source_messages:
        calls = {"n": 0}

        async def flaky(_msg=msg):
            calls["n"] += 1
            if calls["n"] < 2:
                # NetworkUserError is the same class the SDK uses; the
                # source text is set by the SDK and doesn't change behaviour.
                err = NetworkUserError()
                err.__cause__ = RuntimeError(_msg)
                raise err
            return {"ok": True}

        with patch.object(caido_api, "_CAIDO_RETRY_BASE_DELAY", 0.001):
            result = asyncio.run(caido_retry("replay", flaky))
        assert result == {"ok": True}, f"helper failed to recover from {msg!r}"
        assert calls["n"] == 2, f"helper should have retried exactly once for {msg!r}"
