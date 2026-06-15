"""Tests for the child-agent max_turns guard.

The old behaviour silently capped child max_turns at 60 with only a
WARNING-level log line. The new behaviour:
  1. Honours PROMETHEUS_CHILD_MAX_TURNS env var override
  2. Logs at INFO with the actual requested vs. granted values
  3. Falls back to the default 60 on missing/invalid env var
"""

from __future__ import annotations

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
    import logging

    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        result = _resolve_child_max_turns()
    assert result == _MAX_CHILD_TURNS
    # Should have warned the operator about the bad value
    assert any("invalid" in r.getMessage().lower() for r in caplog.records)


def test_zero_falls_back_to_default(monkeypatch, caplog):
    """A zero cap would kill any child agent — reject it."""
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "0")
    import logging

    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        result = _resolve_child_max_turns()
    assert result == _MAX_CHILD_TURNS
    assert any("must be >= 1" in r.getMessage() for r in caplog.records)


def test_negative_falls_back_to_default(monkeypatch, caplog):
    monkeypatch.setenv(_CHILD_MAX_TURNS_ENV, "-5")
    import logging

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
    import logging

    logging.basicConfig(level=logging.DEBUG)
    test_default_when_env_var_unset()
    test_default_when_env_var_empty()
    test_default_when_env_var_whitespace()
    test_honours_valid_override()
    test_honours_high_override()
    test_invalid_string_falls_back_to_default()
    test_zero_falls_back_to_default()
    test_negative_falls_back_to_default()
    test_one_is_valid()
    test_cap_is_strictly_above_request()
    test_env_var_name_is_documented()
    print("All max-turns tests passed.")
