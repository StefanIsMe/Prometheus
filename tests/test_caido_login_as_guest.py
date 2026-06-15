"""Tests for the Caido ``loginAsGuest`` connect-wait fix.

The audit of 175 scan-run logs (Phase 1B) found that 161/175 logs wasted
the very first ``loginAsGuest`` attempt on a connection-refused error
because the Caido GraphQL listener had not yet bound to the container's
port. The fix adds an ``initial_delay`` before the first attempt and
bumps the per-attempt sleep floor to 1.0 s.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.runtime import caido_bootstrap  # noqa: E402
from prometheus.runtime.caido_bootstrap import _login_as_guest  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResult:
    """Mimics an ``ExecResult``-shaped object used by the sandbox session."""

    def __init__(
        self, *, ok: bool, stdout: bytes = b"", stderr: bytes = b"", exit_code: int = 0
    ) -> None:
        self._ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code

    def ok(self) -> bool:
        return self._ok


def _ok_token(token: str = "tok-abc") -> _FakeResult:
    return _FakeResult(
        ok=True,
        stdout=json.dumps(
            {
                "data": {"loginAsGuest": {"token": {"accessToken": token}}},
            }
        ).encode(),
    )


def _fail(exit_code: int = 7, msg: str = "connection refused") -> _FakeResult:
    return _FakeResult(ok=False, stderr=msg.encode(), exit_code=exit_code)


# ---------------------------------------------------------------------------
# 1. Unit: happy path — token on first attempt
# ---------------------------------------------------------------------------


def test_login_as_guest_returns_token_on_first_attempt():
    """When the Caido listener is up on the first probe, _login_as_guest
    must return the token without retries (and without the per-attempt
    floor sleep at the end of the loop)."""
    session = SimpleNamespace()
    session.exec = AsyncMockOK(_ok_token("tok-1"))

    # initial_delay=0 to keep the test fast; the new behaviour is opt-in
    # via the initial_delay default of 0.5
    with patch.object(caido_bootstrap.asyncio, "sleep", new=AsyncMockNoop()):
        token = asyncio.run(_login_as_guest(session, container_url="http://x", initial_delay=0))
    assert token == "tok-1"
    assert session.exec.call_count == 1


# ---------------------------------------------------------------------------
# 2. Unit: failure path — every attempt fails
# ---------------------------------------------------------------------------


def test_login_as_guest_raises_after_exhausting_attempts():
    """When every attempt fails, _login_as_guest must raise RuntimeError
    after exactly ``attempts`` calls."""
    session = SimpleNamespace()
    session.exec = AsyncMockOK(_fail())

    with patch.object(caido_bootstrap.asyncio, "sleep", new=AsyncMockNoop()):
        with pytest.raises(RuntimeError) as exc_info:
            asyncio.run(
                _login_as_guest(
                    session,
                    container_url="http://x",
                    attempts=3,
                    initial_delay=0,
                )
            )
    assert "loginAsGuest failed after 3 attempts" in str(exc_info.value)
    assert session.exec.call_count == 3


# ---------------------------------------------------------------------------
# 3. Unit: connect-wait — initial_delay is awaited before the first probe
# ---------------------------------------------------------------------------


def test_login_as_guest_sleeps_initial_delay_before_first_attempt():
    """The new ``initial_delay=0.5`` parameter must be awaited before the
    first ``session.exec`` call. This is the Phase 1B fix that eliminates
    the 161/175 wasted first-attempt connection-refused errors."""
    session = SimpleNamespace()
    session.exec = AsyncMockOK(_ok_token("tok-2"))

    sleep_calls: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleep_calls.append(s)

    with patch.object(caido_bootstrap.asyncio, "sleep", new=fake_sleep):
        token = asyncio.run(_login_as_guest(session, container_url="http://x", initial_delay=0.5))
    assert token == "tok-2"
    # First sleep is the initial_delay (0.5), then the per-attempt floor (1.0)
    # at the end of the loop. (The first attempt succeeded, so the floor
    # sleep is also awaited — that's the existing behaviour.)
    assert sleep_calls[0] == 0.5, (
        f"first sleep should be the initial_delay=0.5, got {sleep_calls[0]}"
    )
    assert all(s >= 1.0 for s in sleep_calls[1:]), (
        f"per-attempt sleep should be at least 1.0 s, got {sleep_calls[1:]}"
    )


# ---------------------------------------------------------------------------
# 4. Unit: per-attempt sleep floor is at least 1.0 s
# ---------------------------------------------------------------------------


def test_login_as_guest_per_attempt_sleep_floor_is_one_second():
    """After a failed attempt, the backoff must be at least 1.0 s even
    on the first failure (previously the floor was 0)."""
    session = SimpleNamespace()
    # First two attempts fail, third succeeds
    session.exec = AsyncMockSequence(_fail(), _fail(), _ok_token("tok-3"))

    sleep_calls: list[float] = []

    async def fake_sleep(s: float) -> None:
        sleep_calls.append(s)

    with patch.object(caido_bootstrap.asyncio, "sleep", new=fake_sleep):
        token = asyncio.run(
            _login_as_guest(
                session,
                container_url="http://x",
                initial_delay=0,
            )
        )
    assert token == "tok-3"
    # The sleeps between attempts must all be >= 1.0 s
    between_attempts = sleep_calls  # initial_delay=0, so no leading sleep
    assert between_attempts, "expected at least one backoff sleep"
    for s in between_attempts:
        assert s >= 1.0, f"per-attempt backoff below 1.0 s floor: {s}"


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class AsyncMockOK:
    """An async-callable that returns a single pre-set result for every call."""

    def __init__(self, result: _FakeResult) -> None:
        self._result = result
        self.call_count = 0

    async def __call__(self, *args, **kwargs) -> _FakeResult:
        self.call_count += 1
        return self._result


class AsyncMockSequence:
    """An async-callable that returns successive results."""

    def __init__(self, *results: _FakeResult) -> None:
        self._results = list(results)
        self.call_count = 0

    async def __call__(self, *args, **kwargs) -> _FakeResult:
        self.call_count += 1
        if not self._results:
            raise AssertionError("AsyncMockSequence: no more results queued")
        return self._results.pop(0)


class AsyncMockNoop:
    """An async-callable that returns None and records calls."""

    def __init__(self) -> None:
        self.call_count = 0

    async def __call__(self, *args, **kwargs) -> None:
        self.call_count += 1
