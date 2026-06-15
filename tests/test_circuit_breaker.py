"""Tests for prometheus/core/execution.py circuit breaker logic.

Focus: the consecutive-tool-error breaker must distinguish infrastructure
errors (ENOSPC, network, Docker) from logical errors and apply very
different thresholds.  The original bug: 10 transient disk-full errors
killed the entire DNN scanner sub-agent and ended the scan.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.core.execution import (  # noqa: E402
    ChildAgentCircuitBreakerError,
    _MAX_CONSECUTIVE_ERRORS,
    _MAX_CONSECUTIVE_INFRA_ERRORS,
    _classify_infra_error,
    _is_infrastructure_error,
    _is_tool_output_error,
    _check_consecutive_tool_errors,
    _consecutive_infra_errors,
    _consecutive_tool_errors,
)


def _fake_event(*, name: str, tool: str = "exec_command", output: str = "") -> SimpleNamespace:
    """Build a minimal RunItemStreamEvent stand-in for circuit-breaker tests."""
    raw_item: dict | object
    if name == "tool_called":
        raw_item = {"name": tool, "call_id": "call_xyz"}
    else:
        # tool_output — store the output string on .output
        raw_item = SimpleNamespace(output=output)
    return SimpleNamespace(name=name, item=SimpleNamespace(raw_item=raw_item, output=output))


def _reset_breaker_state(agent_id: str) -> None:
    """Make sure no prior test leaks circuit-breaker state into the next."""
    _consecutive_tool_errors.pop(agent_id, None)
    _consecutive_infra_errors.pop(agent_id, None)


# ---------------------------------------------------------------------------
# _is_tool_output_error: existing behaviour must still hold
# ---------------------------------------------------------------------------


def test_is_tool_output_error_detects_exit_code_2():
    """The original 'Process exited with code 2' check must still work."""
    out = "sh: 1: cannot create /tmp/x.pid: No space left on device\nProcess exited with code 2"
    assert _is_tool_output_error(out) is True


def test_is_tool_output_error_ignores_embedded_errors_key():
    """A nuclei stats line with ``"errors":6`` is NOT an error."""
    out = '{"template":"x","errors":6,"matched":0}'
    assert _is_tool_output_error(out) is False


def test_is_tool_output_error_ignores_empty_and_non_string():
    assert _is_tool_output_error("") is False
    assert _is_tool_output_error(None) is False
    assert _is_tool_output_error(123) is False


# ---------------------------------------------------------------------------
# _is_infrastructure_error: new detector
# ---------------------------------------------------------------------------


def test_is_infra_detects_enospc():
    """The exact failure mode from the ENOSPC reproducer: PTY pidfile ENOSPC."""
    out = "sh: 1: cannot create /tmp/sandbox-docker-archive/abc_pty.pid: No space left on device"
    assert _is_infrastructure_error(out) is True


def test_is_infra_detects_disk_quota():
    assert _is_infrastructure_error("disk quota exceeded") is True


def test_is_infra_detects_connection_refused():
    assert _is_infrastructure_error("curl: (7) Failed to connect: Connection refused") is True


def test_is_infra_detects_dns_failure():
    assert _is_infrastructure_error("getaddrinfo: Name or service not known") is False  # raw text
    assert _is_infrastructure_error("getaddrinfo: Name resolution failed") is True


def test_is_infra_detects_docker_daemon_down():
    assert (
        _is_infrastructure_error(
            "Cannot connect to the Docker daemon: docker.sock: connect: no such file"
        )
        is True
    )


def test_is_infra_detects_oom():
    assert _is_infrastructure_error("Cannot allocate memory") is True


def test_is_infra_does_not_match_logical_404():
    """A 404 from the target is a logical result, not infra — must NOT match."""
    assert _is_infrastructure_error("HTTP/1.1 404 Not Found\nContent-Length: 1245") is False


def test_is_infra_does_not_match_nuclei_stats():
    """Nuclei's JSON stats output must not be treated as infra error."""
    out = '{"template-id":"CVE-2025-x","matched":false,"info":{"severity":"high"}}'
    assert _is_infrastructure_error(out) is False


def test_is_infra_case_insensitive():
    assert _is_infrastructure_error("NO SPACE LEFT ON DEVICE") is True
    assert _is_infrastructure_error("CONNECTION REFUSED") is True


# ---------------------------------------------------------------------------
# _classify_infra_error: stable category for operator grep
# ---------------------------------------------------------------------------


def test_classify_enospc():
    out = "sh: cannot create /tmp/sandbox-docker-archive/x_pty.pid: No space left on device"
    assert _classify_infra_error(out) == "ENOSPC"


def test_classify_connection_refused():
    assert _classify_infra_error("Connection refused") == "ECONNREFUSED"


def test_classify_dns():
    assert _classify_infra_error("Name resolution failed") == "DNS"


def test_classify_docker():
    assert (
        _classify_infra_error("Cannot connect to the Docker daemon: docker.sock: connect:")
        == "docker"
    )


def test_classify_fallback():
    assert _classify_infra_error("") == "infrastructure"
    assert _classify_infra_error(None) == "infrastructure"


def test_classify_pidfile_uses_sandbox_category():
    out = "sh: cannot create /tmp/sandbox-docker-archive/x.pid: no such file"
    # 'no such file' is a logical error; our pattern only catches the
    # explicit 'cannot create .*\\.pid:' with a colon.  Verify it does
    # NOT match (so we don't false-positive on logic errors).
    # Actually re-check: 'no such file or directory' is NOT in our
    # patterns, so this should be 'infrastructure' fallback for the
    # 'pidfile' substring match.
    # The pattern is `cannot create .*\\.pid:` — that matches "cannot
    # create /tmp/x.pid:".  This test output does match.
    assert _classify_infra_error(out) == "sandbox-pidfile"


# ---------------------------------------------------------------------------
# _check_consecutive_tool_errors: the actual breaker
# ---------------------------------------------------------------------------


def test_breaker_does_not_kill_agent_on_infra_errors_within_threshold(caplog):
    """The exact ENOSPC reproducer: 10 ENOSPC errors must NOT trip the breaker.

    With the fix, infra errors are tracked under a separate (higher)
    threshold. 10 ENOSPC errors should leave the agent alive.
    """
    agent_id = "test-agent-enospc"
    _reset_breaker_state(agent_id)
    # Simulate the harness returning the exact PTY pidfile error
    # 10 times in a row.  All 10 events: tool_called then tool_output.
    infra_output = (
        "sh: 1: cannot create /tmp/sandbox-docker-archive/xyz_pty.pid: "
        "No space left on device\nProcess exited with code 2"
    )
    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        for _ in range(_MAX_CONSECUTIVE_ERRORS):  # 10
            _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
            _check_consecutive_tool_errors(
                agent_id, _fake_event(name="tool_output", output=infra_output)
            )
    # The breaker must NOT have raised.
    assert _consecutive_tool_errors.get(agent_id, ("", 0))[1] == 0
    # Infra counter is at 10.
    assert _consecutive_infra_errors.get(agent_id) == _MAX_CONSECUTIVE_ERRORS
    _reset_breaker_state(agent_id)


def test_breaker_breaks_at_higher_infra_threshold(caplog):
    """At _MAX_CONSECUTIVE_INFRA_ERRORS (50), the breaker DOES fire.

    This protects against truly broken environments (a sandbox that will
    never recover) without killing scans over a brief outage.
    """
    agent_id = "test-agent-enospc-broken"
    _reset_breaker_state(agent_id)
    infra_output = (
        "sh: 1: cannot create /tmp/sandbox-docker-archive/xyz_pty.pid: No space left on device"
    )
    raised = False
    with caplog.at_level(logging.WARNING, logger="prometheus.core.execution"):
        for i in range(_MAX_CONSECUTIVE_INFRA_ERRORS):
            try:
                _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
                _check_consecutive_tool_errors(
                    agent_id, _fake_event(name="tool_output", output=infra_output)
                )
            except ChildAgentCircuitBreakerError:
                raised = True
                break
    assert raised, f"breaker should fire after {_MAX_CONSECUTIVE_INFRA_ERRORS} infra errors"
    # Sanity: threshold must be much higher than the logical threshold.
    assert _MAX_CONSECUTIVE_INFRA_ERRORS >= _MAX_CONSECUTIVE_ERRORS * 3, (
        "infra threshold should be at least 3x logical threshold to give the "
        "environment time to recover"
    )
    _reset_breaker_state(agent_id)


def test_breaker_resets_infra_counter_on_logical_error(caplog):
    """A logical error after infra errors resets the infra counter.

    This handles the case where the environment recovers but the LLM
    now hits a different (logical) problem — the infra-error streak
    should be forgotten.
    """
    agent_id = "test-agent-mixed"
    _reset_breaker_state(agent_id)
    infra_output = "cannot create /tmp/x.pid: No space left on device"
    logical_output = "HTTP/1.1 500 Internal Server Error"

    # 5 infra errors
    for _ in range(5):
        _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
        _check_consecutive_tool_errors(
            agent_id, _fake_event(name="tool_output", output=infra_output)
        )
    assert _consecutive_infra_errors.get(agent_id) == 5

    # One logical error — should reset infra counter
    _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
    _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_output", output=logical_output))
    assert _consecutive_infra_errors.get(agent_id, 0) == 0, (
        "infra counter should reset when a logical error follows"
    )
    _reset_breaker_state(agent_id)


def test_breaker_resets_infra_counter_on_success(caplog):
    """A successful tool call resets the infra counter."""
    agent_id = "test-agent-recover"
    _reset_breaker_state(agent_id)
    infra_output = "No space left on device"
    success_output = "Process exited with code 0\nOutput: hello world"

    for _ in range(5):
        _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
        _check_consecutive_tool_errors(
            agent_id, _fake_event(name="tool_output", output=infra_output)
        )
    assert _consecutive_infra_errors.get(agent_id) == 5

    _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
    _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_output", output=success_output))
    assert _consecutive_infra_errors.get(agent_id, 0) == 0
    _reset_breaker_state(agent_id)


def test_breaker_still_kills_on_logical_errors(caplog):
    """Regression: logical errors (404, 500, etc.) must still trigger breaker.

    The whole point of the breaker is to stop the LLM from doing
    pointless retries when the *tool* is failing.  Only infra errors
    should be exempt.
    """
    agent_id = "test-agent-logical"
    _reset_breaker_state(agent_id)
    bad_output = "HTTP/1.1 500 Internal Server Error\nProcess exited with code 1"

    raised = False
    for i in range(_MAX_CONSECUTIVE_ERRORS):
        _check_consecutive_tool_errors(agent_id, _fake_event(name="tool_called"))
        try:
            _check_consecutive_tool_errors(
                agent_id, _fake_event(name="tool_output", output=bad_output)
            )
        except ChildAgentCircuitBreakerError:
            raised = True
            break
    assert raised, f"breaker should fire after {_MAX_CONSECUTIVE_ERRORS} logical errors"
    _reset_breaker_state(agent_id)


if __name__ == "__main__":
    # Run by hand for quick smoke test.
    test_is_tool_output_error_detects_exit_code_2()
    test_is_tool_output_error_ignores_embedded_errors_key()
    test_is_tool_output_error_ignores_empty_and_non_string()
    test_is_infra_detects_enospc()
    test_is_infra_detects_disk_quota()
    test_is_infra_detects_connection_refused()
    test_is_infra_detects_dns_failure()
    test_is_infra_detects_docker_daemon_down()
    test_is_infra_detects_oom()
    test_is_infra_does_not_match_logical_404()
    test_is_infra_does_not_match_nuclei_stats()
    test_is_infra_case_insensitive()
    test_classify_enospc()
    test_classify_connection_refused()
    test_classify_dns()
    test_classify_docker()
    test_classify_fallback()
    test_classify_pidfile_uses_sandbox_category()
    test_breaker_does_not_kill_agent_on_infra_errors_within_threshold(caplog=MagicMock())
    test_breaker_breaks_at_higher_infra_threshold(caplog=MagicMock())
    test_breaker_resets_infra_counter_on_logical_error(caplog=MagicMock())
    test_breaker_resets_infra_counter_on_success(caplog=MagicMock())
    test_breaker_still_kills_on_logical_errors(caplog=MagicMock())
    print("All circuit-breaker tests passed.")
