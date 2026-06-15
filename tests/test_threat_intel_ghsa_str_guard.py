"""Tests for the GHSA ``cvss`` str-vs-dict guard (Phase 1C).

The audit of 175 scan-run logs (Phase 1C) found 16 occurrences of
``'str' object has no attribute 'get'`` from the GHSA query code path.
Root cause: ``(adv.get("cvss") or {}).get("score", 0.0) or 0.0`` — when
``adv["cvss"]`` is a string (a serialised CVSS vector the API sometimes
returns instead of an object), the ``or {}`` doesn't kick in (non-empty
strings are truthy) and the subsequent ``.get(...)`` raises
``AttributeError``.

The fix is a small ``_cvss_score`` helper that handles dict / string /
None uniformly and a ``_pkg_dict`` helper for the same shape of bug in
the package-version comparison path.

These tests verify:

  1. _cvss_score returns 0.0 for the string payload (the audit's case).
  2. _cvss_score returns the score for the normal dict payload.
  3. _pkg_dict returns {} for a string package.
  4. E2E log-replay: the recorded mheducation-com_0887 prometheus.log that
     contains the exact error is now a no-op (no AttributeError).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.tools.threat_intel import tool as ti_tool  # noqa: E402
from prometheus.tools.threat_intel.tool import _cvss_score, _pkg_dict  # noqa: E402


# ---------------------------------------------------------------------------
# 1. _cvss_score handles the audit's exact failure case
# ---------------------------------------------------------------------------


def test_cvss_score_handles_string_payload():
    """The audit's exact failure mode: adv["cvss"] is a string.

    Before the fix, the chained expression raised
    ``AttributeError: 'str' object has no attribute 'get'``. The new
    helper must return 0.0 for any non-dict value."""
    # The exact shape from the audit's log line:
    #   GHSA query failed for 'Java' (high): 'str' object has no attribute 'get'
    adv = {"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    # Must not raise
    score = _cvss_score(adv)
    assert score == 0.0


def test_cvss_score_handles_normal_dict_payload():
    """The normal happy path: adv["cvss"] is a dict with a score."""
    adv = {"cvss": {"score": 7.5}}
    assert _cvss_score(adv) == 7.5


def test_cvss_score_handles_missing_cvss():
    """When adv has no 'cvss' key at all, return 0.0."""
    assert _cvss_score({}) == 0.0
    assert _cvss_score({"cvss": None}) == 0.0


def test_cvss_score_handles_empty_dict_cvss():
    """When adv["cvss"] is an empty dict, return 0.0."""
    assert _cvss_score({"cvss": {}}) == 0.0


def test_cvss_score_handles_dict_with_non_numeric_score():
    """When adv["cvss"] has a non-numeric score, return 0.0."""
    assert _cvss_score({"cvss": {"score": "unknown"}}) == 0.0


def test_cvss_score_handles_int_score():
    """Integer scores (CVSS v2) must be returned as float."""
    assert _cvss_score({"cvss": {"score": 5}}) == 5.0


# ---------------------------------------------------------------------------
# 2. _pkg_dict handles the same shape of bug
# ---------------------------------------------------------------------------


def test_pkg_dict_handles_dict():
    assert _pkg_dict({"name": "next"}) == {"name": "next"}


def test_pkg_dict_handles_empty_dict():
    assert _pkg_dict({}) == {}


def test_pkg_dict_handles_string():
    """When the API returns a string instead of a package object,
    _pkg_dict must return {} so the subsequent .get() doesn't raise."""
    # Must not raise
    result = _pkg_dict("next")
    assert result == {}


def test_pkg_dict_handles_none():
    assert _pkg_dict(None) == {}


# ---------------------------------------------------------------------------
# 3. E2E log-replay: the exact mheducation-com_0887 failure case
# ---------------------------------------------------------------------------


def _load_mheducation_log() -> Path:
    """Return the path of the recorded mheducation-com_0887 prometheus.log
    that contains the ``'str' object has no attribute 'get'`` error."""
    runs_root = SOURCE_ROOT / "prometheus_runs"
    preferred = runs_root / "mheducation-com_0887" / "prometheus.log"
    assert preferred.exists(), (
        "the recorded mheducation-com_0887 prometheus.log is missing — "
        "the audit's bug fixture has been pruned"
    )
    return preferred


def test_log_replay_mheducation_0887_gc_string_payload_no_longer_raises():
    """The recorded mheducation-com_0887 prometheus.log contains the exact
    error ``GHSA query failed for 'Java' (high): 'str' object has no
    attribute 'get'``. With the new ``_cvss_score`` helper in place,
    feeding the same payload shape into the function must NOT raise
    ``AttributeError``."""
    log_path = _load_mheducation_log()
    text = log_path.read_text(errors="replace")
    # Sanity: this log really does have the bug
    assert "GHSA query failed for 'Java'" in text, (
        f"log {log_path} does not contain the recorded GHSA failure"
    )
    assert "'str' object has no attribute 'get'" in text, (
        f"log {log_path} does not contain the recorded AttributeError"
    )

    # The audit's payload: a CVSS vector string. Run the helper and
    # assert it does not raise.
    payload_adv = {"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    score = _cvss_score(payload_adv)
    assert score == 0.0

    # And the same for the package dict shape (REST fallback path)
    payload_vuln = {"package": "next", "vulnerableVersionRange": "<13.5.0"}
    pkg = _pkg_dict(payload_vuln.get("package", {}))
    assert pkg == {}


def test_log_replay_mheducation_0887_count_of_failures_documented():
    """Sanity check on the log fixture: count the 'str' error lines so
    we know exactly how many real scan runs this fix is expected to
    silence."""
    log_path = _load_mheducation_log()
    text = log_path.read_text(errors="replace")
    n = text.count("GHSA query failed for 'Java'")
    assert n >= 1, "log should have at least one GHSA failure for Java"
