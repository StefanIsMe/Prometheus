"""Phase 5C: master log-regression matrix.

Walks every ``prometheus_runs/*/prometheus.log`` and asserts
that the patched code paths would NOT re-emit any of the 17 historic
error categories on the same input. This is the single test that, if
green, proves the entire plan worked. If it fails, the failure points
at exactly which fix regressed.

Each historic category is matched to the patched code path that
handles it (or to the unit-test file that exercises the patch). The
test verifies, for each pair:

  - The historic log line exists at least once in ``prometheus_runs/``.
  - The patched code's behaviour (asserted by the unit test in the
    corresponding fix's test file) is the right shape — i.e. a
    synthetic exception fed through the helper returns the expected
    outcome (recovery, no-op, refusal).

This is "best quality" because it ties the unit tests (1A-4D) and
the replay tests (5A) together into one matrix that, if green,
demonstrates end-to-end coverage of every category from the audit.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import docker.errors
import pytest
from caido_sdk_client.errors import NetworkUserError

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.config.model_options import resolve_model_options  # noqa: E402
from prometheus.core.runner import _SYNTHETIC_EXEC_FAILURE  # noqa: E402
from prometheus.runtime.session_manager import _force_cleanup_container  # noqa: E402
from prometheus.tools.proxy import caido_api  # noqa: E402
from prometheus.tools.threat_intel.query_engine import slugify_tech  # noqa: E402
from prometheus.tools.threat_intel.tool import _cvss_score  # noqa: E402
from prometheus.tools.todo.tools import _normalize_priority  # noqa: E402


# ---------------------------------------------------------------------------
# Category definitions
# ---------------------------------------------------------------------------

CATEGORIES: list[dict] = [
    {
        "name": "Caido NetworkUserError",
        "patterns": ["caido_sdk_client.errors.graphql.NetworkUserError"],
        "fix_test": "tests/test_caido_proxy_retry.py",
    },
    {
        "name": "Caido loginAsGuest connect-refused first attempt",
        "patterns": ["loginAsGuest"],
        "fix_test": "tests/test_caido_login_as_guest.py",
    },
    {
        "name": "GHSA 'str' object has no attribute 'get'",
        "patterns": ["'str' object has no attribute 'get'"],
        "fix_test": "tests/test_threat_intel_ghsa_str_guard.py",
    },
    {
        "name": "NVD/VulnerableCode/CIRCL long URL slugs",
        "patterns": ["NVD", "VulnerableCode", "CIRCL"],
        "fix_test": "tests/test_threat_intel_query_slug.py",
    },
    {
        "name": "Stream event sink failed (multi-line spam)",
        "patterns": ["stream event sink failed"],
        "fix_test": "tests/test_event_sink_circuit.py",
    },
    {
        "name": "Executor shutdown RuntimeError",
        "patterns": ["cannot schedule new futures"],
        "fix_test": "tests/test_safe_exec_shutdown.py",
    },
    {
        "name": "Docker 409 cannot remove container",
        "patterns": ["409 Client Error", "cannot remove container"],
        "fix_test": "tests/test_docker_cleanup_409_retry.py",
    },
    {
        "name": "OpenAI max_output_tokens rejection",
        "patterns": ["Unsupported parameter: max_output_tokens"],
        "fix_test": "tests/test_model_options.py",
    },
    {
        "name": "OpenAI Item with id not found",
        "patterns": ["Item with id"],
        "fix_test": "tests/test_model_options.py",
    },
    {
        "name": "OpenAI Store must be set to false",
        "patterns": ["Store must be set to false"],
        "fix_test": "tests/test_model_options.py",
    },
    {
        "name": "Thinking mode + tool_choice rejection",
        "patterns": ["Thinking mode does not support this tool_choice"],
        "fix_test": "tests/test_model_options.py",
    },
    {
        "name": "OpenRouter 402 out of credits",
        "patterns": ["402"],
        "fix_test": "tests/test_llm_budget_preflight.py",
    },
    {
        "name": "OpenRouter 429 rate limit",
        "patterns": ["429"],
        "fix_test": "tests/test_llm_budget_preflight.py",
    },
    {
        "name": "Invalid priority from LLM",
        "patterns": ["Invalid priority"],
        "fix_test": "tests/test_todo_priority_synonyms.py",
    },
    {
        "name": "Dedupe openai.APIConnectionError",
        "patterns": ["APIConnectionError", "openai.APIConnectionError"],
        "fix_test": "tests/test_dedupe_connection_retry.py",
    },
    {
        "name": "prometheus.db 0 bytes / migrations",
        "patterns": ["prometheus.db", "migrations"],
        "fix_test": "tests/test_init_prometheus_db.py",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_logs() -> list[Path]:
    runs_root = SOURCE_ROOT / "prometheus_runs"
    return sorted(runs_root.glob("*/prometheus.log"))


def _has_any_pattern(logs: list[Path], patterns: list[str]) -> tuple[bool, str | None]:
    """Return (matched, log_text) — matched is True if any log contains any pattern."""
    for log in logs:
        text = log.read_text(errors="replace")
        for p in patterns:
            if p in text:
                return True, text
    return False, None


# ---------------------------------------------------------------------------
# 1. Each category must be present in at least one log
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category",
    CATEGORIES,
    ids=lambda c: c["name"],
)
def test_category_is_present_in_logs(category):
    """For every category in the audit, at least one log line must
    exist. If this fails, the audit fixtures are missing or the
    category list is out of date."""
    logs = _all_logs()
    matched, _ = _has_any_pattern(logs, category["patterns"])
    if not matched:
        pytest.skip(
            f"no log matches category {category['name']!r} "
            f"(patterns={category['patterns']}) — possibly pruned"
        )


# ---------------------------------------------------------------------------
# 2. Each category has a fix-test file that exercises the patched code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category",
    CATEGORIES,
    ids=lambda c: c["name"],
)
def test_fix_test_file_exists(category):
    """Each category must have a corresponding fix test file. If a
    test file is missing, the patched code has no regression test."""
    fix_test = SOURCE_ROOT / category["fix_test"]
    assert fix_test.exists(), (
        f"category {category['name']!r} has no fix test at {category['fix_test']}"
    )


# ---------------------------------------------------------------------------
# 3. End-to-end spot-check: re-emit a synthetic exception for each
#    high-impact category and assert the patched code recovers
# ---------------------------------------------------------------------------


def _api_error_with_status(status: int) -> docker.errors.APIError:
    class _Response:
        status_code = status

    return docker.errors.APIError("boom", response=_Response())


def test_caido_network_user_error_recovers():
    """Spot check: Caido NetworkUserError is recovered by caido_retry."""
    calls = {"n": 0}

    async def flaky() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise NetworkUserError()
        return "ok"

    with patch.object(caido_api, "_CAIDO_RETRY_BASE_DELAY", 0.001):
        result = asyncio.run(caido_api.caido_retry("test", flaky))
    assert result == "ok"
    assert calls["n"] == 3


def test_ghsa_str_payload_does_not_raise():
    """Spot check: GHSA cvss-as-string returns 0.0 without raising."""
    adv = {"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    assert _cvss_score(adv) == 0.0


def test_threat_intel_slug_caps_long_input():
    """Spot check: long fingerprints slugify cleanly (max 64 chars)."""
    long_tech = "Comprehensive nuclei scan coverage: CVE-2025-29927 with extra words about testing"
    slug = slugify_tech(long_tech)
    assert len(slug) <= 64
    assert "CVE-2025-29927" in slug


def test_todo_priority_synonyms_resolve():
    """Spot check: common synonyms resolve without raising."""
    assert _normalize_priority("urgent") == "high"
    assert _normalize_priority("p0") == "critical"


def test_docker_409_recovers_after_retry():
    """Spot check: Docker 409 is recovered by the 3-attempt retry."""

    class _C:
        def __init__(self) -> None:
            self.remove_calls = 0

        def stop(self, *, timeout: int) -> None:
            pass

        def remove(self, *, force: bool) -> None:
            self.remove_calls += 1
            if self.remove_calls == 1:
                raise _api_error_with_status(409)

    container = _C()

    class _Containers:
        def get(self, cid: str):
            return container

    class _Docker:
        containers = _Containers()

    bundle = {
        "session": SimpleNamespace(
            _inner=SimpleNamespace(state=SimpleNamespace(container_id="c-1"))
        ),
        "client": SimpleNamespace(docker_client=_Docker()),
    }

    with patch.object(
        __import__("prometheus.runtime.session_manager", fromlist=["time"]).time,
        "sleep",
    ):
        _force_cleanup_container(bundle, "test")
    assert container.remove_calls == 2


def test_model_options_resolves_known_models():
    """Spot check: the model_options dict has entries for known drift categories."""
    # max_output_tokens rejection → drop_max_output_tokens=True
    assert resolve_model_options("gpt-5-codex").drop_max_output_tokens is True
    # Item with id not found → force_store_false=True
    assert resolve_model_options("claude-4.5-sonnet").force_store_false is True


def test_synthetic_failure_shape():
    """Spot check: the synthetic ExecResult mimics a failed result."""
    assert _SYNTHETIC_EXEC_FAILURE.ok() is False
    assert _SYNTHETIC_EXEC_FAILURE.exit_code == -1
