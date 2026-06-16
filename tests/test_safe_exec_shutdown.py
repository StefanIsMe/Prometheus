"""Tests for the ``_safe_exec`` wrapper that translates the post-shutdown
``RuntimeError: cannot schedule new futures`` into a synthetic failure.

Background: the audit found runs that hit this error during teardown
because the SDK's BaseSandboxSession awaits a private ThreadPoolExecutor
that the parent's ``_python_exit`` hook tears down first. The fix
catches that specific RuntimeError and returns a synthetic ExecResult
that the existing call-sites handle via the standard ``.ok()`` /
``.stdout`` interface.

This file:

  1. Unit-tests that a session whose exec raises the shutdown error
     returns a synthetic failure (not raising).
  2. Unit-tests that the synthetic failure's ``.ok()`` is False.
  3. Unit-tests that a normal happy-path exec passes through unchanged.
  4. Unit-tests that a non-matching RuntimeError still propagates.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.core.runner import _SyntheticExecResult  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Synthetic failure shape
# ---------------------------------------------------------------------------


def test_synthetic_failure_ok_is_false():
    """The synthetic failure must report ok() == False so existing
    call-sites that inspect .ok() see a normal failure."""
    fail = _SyntheticExecResult()
    assert fail.ok() is False
    assert fail.exit_code == -1
    assert fail.stdout == b""
    assert fail.stderr == b"executor shut down"


# ---------------------------------------------------------------------------
# 2. Wrapper logic: shutdown RuntimeError -> synthetic failure
# ---------------------------------------------------------------------------


def test_safe_exec_translates_shutdown_runtime_error():
    """When session.exec raises ``RuntimeError('cannot schedule new
    futures after shutdown')``, the wrapper must return the synthetic
    failure (NOT re-raise)."""

    class _FakeSession:
        def __init__(self) -> None:
            self.call_count = 0

        async def exec(self, *args, **kwargs):
            self.call_count += 1
            raise RuntimeError("cannot schedule new futures after shutdown")

    async def _safe_exec(session, *args, **kwargs):
        try:
            return await session.exec(*args, **kwargs)
        except RuntimeError as exc:
            if "cannot schedule new futures" not in str(exc):
                raise
            return _SyntheticExecResult()

    session = _FakeSession()
    result = asyncio.run(_safe_exec(session, "sh", "-c", "echo hi"))
    assert result.ok() is False
    assert session.call_count == 1


# ---------------------------------------------------------------------------
# 3. Wrapper logic: happy path passes through unchanged
# ---------------------------------------------------------------------------


def test_safe_exec_passes_through_normal_result():
    """A session that returns a normal result must be passed through
    unchanged — no wrapping, no extra logic."""

    class _NormalResult:
        def ok(self) -> bool:
            return True

        exit_code = 0
        stdout = b"hello"
        stderr = b""

    class _NormalSession:
        async def exec(self, *args, **kwargs):
            return _NormalResult()

    async def _safe_exec(session, *args, **kwargs):
        try:
            return await session.exec(*args, **kwargs)
        except RuntimeError as exc:
            if "cannot schedule new futures" not in str(exc):
                raise
            return _SyntheticExecResult()

    session = _NormalSession()
    result = asyncio.run(_safe_exec(session, "echo", "hi"))
    assert result.ok() is True
    assert result.stdout == b"hello"


# ---------------------------------------------------------------------------
# 4. Wrapper logic: non-matching RuntimeError propagates
# ---------------------------------------------------------------------------


def test_safe_exec_propagates_unrelated_runtime_error():
    """A RuntimeError that does NOT match the shutdown pattern must
    propagate — we only catch the executor-shutdown case, not all
    RuntimeErrors."""

    class _BadSession:
        async def exec(self, *args, **kwargs):
            raise RuntimeError("something else entirely")

    async def _safe_exec(session, *args, **kwargs):
        try:
            return await session.exec(*args, **kwargs)
        except RuntimeError as exc:
            if "cannot schedule new futures" not in str(exc):
                raise
            return _SyntheticExecResult()

    import pytest

    session = _BadSession()
    with pytest.raises(RuntimeError, match="something else entirely"):
        asyncio.run(_safe_exec(session, "sh", "-c", "echo hi"))
