"""Tests for the Docker 409-cleanup retry helper in session_manager.

Background: the audit found 7 runs that hit
``docker.errors.APIError 409 cannot remove container`` because the
container was still spinning up after ``client.delete`` returned.
The fix retries ``remove(force=True)`` up to 3 times with 2-second
backoff, and swallows ``docker.errors.NotFound`` for already-removed
containers.

This file:

  1. Unit-tests that a container whose ``remove()`` raises ``APIError(409)``
     on the first call and succeeds on the second is retried exactly once
     (and the WARNING is logged once).
  2. Unit-tests that a container whose ``remove()`` raises ``NotFound`` is
     logged at INFO and the helper returns cleanly.
  3. Unit-tests that a container whose ``remove()`` keeps raising
     ``APIError(409)`` exhausts 3 attempts and logs WARNING 3 times.
  4. Unit-tests that a container whose ``remove()`` raises a non-Docker
     exception logs WARNING and does not retry.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import docker.errors
import pytest

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.runtime import session_manager  # noqa: E402
from prometheus.runtime.session_manager import _force_cleanup_container  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeContainer:
    """A stand-in for a docker.models.containers.Container.

    ``remove`` is a fake that pops a sequence of pre-programmed
    behaviours; each behaviour is either an exception class (with
    optional kwargs) or the string "ok".
    """

    def __init__(self, remove_sequence: list) -> None:
        self._remove_sequence = list(remove_sequence)
        self.remove_calls = 0
        self.stop_called = 0

    def stop(self, *, timeout: int) -> None:
        self.stop_called += 1

    def remove(self, *, force: bool) -> None:
        self.remove_calls += 1
        behaviour = self._remove_sequence.pop(0)
        if isinstance(behaviour, BaseException):
            raise behaviour
        if behaviour == "ok":
            return
        raise AssertionError(f"unknown behaviour: {behaviour!r}")


class _FakeDockerClient:
    def __init__(self, container: object) -> None:
        self._container = container
        self.containers = self
        self.get_calls = 0

    def get(self, container_id: str) -> object:
        self.get_calls += 1
        return self._container


def _bundle(container: object) -> dict:
    return {
        "session": SimpleNamespace(
            _inner=SimpleNamespace(state=SimpleNamespace(container_id="c-1234567890abcdef"))
        ),
        "client": SimpleNamespace(docker_client=_FakeDockerClient(container)),
    }


def _api_error_with_status(status: int, message: str = "conflict") -> docker.errors.APIError:
    """Build a docker.errors.APIError with the given HTTP status code.

    ``APIError.status_code`` is a property derived from
    ``self.response.status_code`` (no public setter), so we attach a
    tiny response stub. This is the same shape the real Docker SDK
    produces when a container hits a 409 conflict.
    """

    class _Response:
        status_code = status

    return docker.errors.APIError(message, response=_Response())


# ---------------------------------------------------------------------------
# 1. APIError 409 on first call, success on second
# ---------------------------------------------------------------------------


def test_409_first_call_succeeds_after_retry(caplog):
    """The helper must retry exactly once and log WARNING once."""
    err = _api_error_with_status(409, "cannot remove container: conflict")
    container = _FakeContainer([err, "ok"])

    with patch.object(session_manager.time, "sleep") as fake_sleep:
        with caplog.at_level(logging.WARNING, logger="prometheus.runtime.session_manager"):
            _force_cleanup_container(_bundle(container), "scan-1")

    assert container.remove_calls == 2
    fake_sleep.assert_called_once_with(2.0)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "409" in warnings[0].getMessage()


# ---------------------------------------------------------------------------
# 2. NotFound on the very first call
# ---------------------------------------------------------------------------


def test_notfound_returns_cleanly(caplog):
    """An already-removed container must log at INFO, not WARNING."""
    err = docker.errors.NotFound("not found")
    container = _FakeContainer([err])

    with caplog.at_level(logging.INFO, logger="prometheus.runtime.session_manager"):
        _force_cleanup_container(_bundle(container), "scan-2")

    assert container.remove_calls == 1
    # The only log line is INFO; no WARNING.
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


# ---------------------------------------------------------------------------
# 3. APIError 409 every call
# ---------------------------------------------------------------------------


def test_409_every_call_exhausts_three_attempts(caplog):
    """Three 409s in a row → 3 attempts, 3 WARNING logs, then a final
    WARNING that cleanup failed."""
    container = _FakeContainer(
        [
            _api_error_with_status(409),
            _api_error_with_status(409),
            _api_error_with_status(409),
        ]
    )

    with patch.object(session_manager.time, "sleep") as fake_sleep:
        with caplog.at_level(logging.WARNING, logger="prometheus.runtime.session_manager"):
            _force_cleanup_container(_bundle(container), "scan-3")

    assert container.remove_calls == 3
    # 2 back-off sleeps (after attempts 1 and 2; no sleep after the 3rd)
    assert fake_sleep.call_count == 2
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    # 2 retry warnings + 1 final "failed to remove" warning
    assert len(warnings) == 3
    assert sum(1 for w in warnings if "409" in w.getMessage()) == 2


# ---------------------------------------------------------------------------
# 4. Non-Docker exception → WARNING, no retry
# ---------------------------------------------------------------------------


def test_non_docker_exception_logs_warning_no_retry(caplog):
    """A non-Docker exception (e.g. KeyError) must log WARNING and
    must not retry (only 409s and NotFound are handled specially)."""
    container = _FakeContainer([KeyError("boom")])

    with caplog.at_level(logging.WARNING, logger="prometheus.runtime.session_manager"):
        _force_cleanup_container(_bundle(container), "scan-4")

    assert container.remove_calls == 1
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
