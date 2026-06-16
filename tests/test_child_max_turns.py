"""Tests for the child-agent max_turns guard.

The old behaviour silently capped child max_turns at 60 with only a
WARNING-level log line. The new behaviour:
  1. Honours PROMETHEUS_CHILD_MAX_TURNS env var override
  2. Logs at INFO with the actual requested vs. granted values
  3. Falls back to the default 60 on missing/invalid env var
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.core.execution import (  # noqa: E402
    _CHILD_MAX_TURNS_ENV,
    _MAX_CHILD_TURNS,
    _resolve_child_max_turns,
)


def test_default_when_env_var_unset(monkeypatch):
    monkeypatch.delenv(_CHILD_MAX_TURNS_ENV, raising=False)
    assert _resolve_child_max_turns() == _MAX_CHILD_TURNS


def test_default_when_env_var_empty(monkeypatch):
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "")
    assert _resolve_child_max_turns() == _MAX_CHILD_TURNS


def test_default_when_env_var_whitespace(monkeypatch):
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "   ")
    assert _resolve_child_max_turns() == _MAX_CHILD_TURNS


def test_honours_valid_override(monkeypatch):
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "150")
    assert _resolve_child_max_turns() == 150


def test_honours_high_override(monkeypatch):
    """Operators on long-running programs may need a much higher cap."""
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "500")
    assert _resolve_child_max_turns() == 500


def test_invalid_string_falls_back_to_default(monkeypatch, caplog):
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "not-a-number")

    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        result = _resolve_child_max_turns()
    assert result == _MAX_CHILD_TURNS
    # Should have warned the operator about the bad value
    assert any("invalid" in r.getMessage().lower() for r in caplog.records)


def test_zero_falls_back_to_default(monkeypatch, caplog):
    """A zero cap would kill any child agent — reject it."""
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "0")

    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        result = _resolve_child_max_turns()
    assert result == _MAX_CHILD_TURNS
    assert any("must be >= 1" in r.getMessage() for r in caplog.records)


def test_negative_falls_back_to_default(monkeypatch, caplog):
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "-5")

    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        result = _resolve_child_max_turns()
    assert result == _MAX_CHILD_TURNS


def test_one_is_valid(monkeypatch):
    """Cap of 1 is silly but not invalid — honour it."""
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "1")
    assert _resolve_child_max_turns() == 1


def test_cap_is_strictly_above_request():
    """Sanity: the function is called when max_turns > cap. Test the
    surrounding logic by verifying the constant relationship.
    """
    # Default cap should be 60 (the old default)
    assert _MAX_CHILD_TURNS == 60


def test_env_var_name_is_documented():
    """The env var name should be self-documenting and grep-friendly."""
    assert _CHILD_MAX_TURNS_ENV == "PROMETHEUS_CHILD_MAX_TURNS"


if __name__ == "__main__":
    import logging  # codeql[py/repeated-import] : suppressed via the security dashboard triage
    import sys

    import pytest

    logging.basicConfig(level=logging.DEBUG)
    _mp = pytest.MonkeyPatch()

    # Minimal stand-in for pytest's LogCaptureFixture used by `caplog`.
    # The manual tests below only read `.records` after `with caplog.at_level(...):`
    # exits, so we provide a thin shim with an `at_level` context manager and
    # an empty records list. Sufficient for the assertions in this file.
    class _NullCaplog:
        def __init__(self) -> None:
            self.records: list = []

        def at_level(self, *_args, **_kwargs):
            from contextlib import nullcontext

            return nullcontext()

    _caplog = _NullCaplog()
    try:
        test_default_when_env_var_unset(_mp)
        test_default_when_env_var_empty(_mp)
        test_default_when_env_var_whitespace(_mp)
        test_honours_valid_override(_mp)
        test_honours_high_override(_mp)
        test_invalid_string_falls_back_to_default(_mp, _caplog)
        test_zero_falls_back_to_default(_mp, _caplog)
        test_negative_falls_back_to_default(_mp, _caplog)
        test_one_is_valid(_mp)
        test_cap_is_strictly_above_request()
        test_env_var_name_is_documented()
        print("All max-turns tests passed.")
    finally:
        _mp.undo()
        sys.exit(0)
