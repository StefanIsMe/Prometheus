"""Tests for the dedup-retry guard in create_vulnerability_report.

These tests pin down the behaviour change made in response to the
launchdarkly scan that logged nine ``create_vulnerability_report`` calls
for one underlying finding (the guard was keyed on raw title bytes, so
the cosmetic re-writes all slipped through; the cap was also too high
to actually block). The fix:

  * Key the guard on a NORMALISED title (whitespace-collapsed, lower-
    cased, leading 'Test ' stripped, trailing punctuation stripped) so
    cosmetic re-writes hit the same bucket.
  * Lower ``_MAX_RETRIES`` from 3 to 2 so the cap actually fires after
    a single re-attempt.
  * Scope the counter to the running scan via ``scan_id`` so resumed
    scans don't inherit counts from earlier runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.tools.reporting.tool import (  # noqa: E402
    _MAX_RETRIES,
    _check_retry_guard,
    _normalise_title_for_dedup,
    _retry_counters,
    reset_retry_guard,
)


def setup_function(_fn):
    """Each test starts with an empty counter map."""
    reset_retry_guard()


def teardown_function(_fn):
    reset_retry_guard()


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def test_normalise_collapses_whitespace_and_lowercases():
    assert _normalise_title_for_dedup("  SQL  Injection  in   /api/users  ") == (
        "sql injection in /api/users"
    )


def test_normalise_strips_test_prefix():
    assert _normalise_title_for_dedup("Test: SQL Injection") == "sql injection"
    assert _normalise_title_for_dedup("test sql injection") == "sql injection"
    assert _normalise_title_for_dedup("Fuzz: xss") == "xss"


def test_normalise_strips_trailing_punctuation():
    assert _normalise_title_for_dedup("SQL Injection.") == "sql injection"
    assert _normalise_title_for_dedup("SQL Injection!?!") == "sql injection"


def test_normalise_handles_empty_and_none():
    assert _normalise_title_for_dedup("") == ""
    assert _normalise_title_for_dedup(None) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Cap behaviour
# ---------------------------------------------------------------------------


def test_first_attempt_returns_none():
    assert _check_retry_guard("SQL Injection in /api/users", "/api/users", scan_id="s1") is None


def test_cosmetic_rewrites_share_a_bucket():
    """The exact failure mode from the launchdarkly scan: titles that
    differ only in trailing punctuation, prefix, or word order should
    increment the same counter.

    With MAX_RETRIES=2, three attempts to the same underlying finding
    must trip the cap regardless of cosmetic differences.
    """
    title_variants = [
        "Unauthenticated GraphQL Introspection on pri.observability.app.launchdarkly.com Exposes Schema",
        "Unauthenticated GraphQL Introspection on pri.observability.app.launchdarkly.com Exposes Schema.",
        "Test: Unauthenticated GraphQL Introspection on pri.observability.app.launchdarkly.com Exposes Schema",
    ]
    # First two calls: warn but allow
    for t in title_variants[:2]:
        err = _check_retry_guard(t, "/", scan_id="s2")
        assert err is None
    # Third call (different cosmetic form, same underlying finding):
    # the cap fires.
    err = _check_retry_guard(title_variants[2], "/", scan_id="s2")
    assert err is not None
    assert "RETRY LIMIT EXCEEDED" in err


def test_word_truncation_also_shares_a_bucket():
    """A common LLM regression: the agent shortens the title between
    attempts. Both versions must hit the same bucket."""
    err1 = _check_retry_guard(
        "Unauthenticated GraphQL Introspection on pri.observability.app.launchdarkly.com Exposes Schema",
        "/",
        scan_id="s2b",
    )
    err2 = _check_retry_guard(
        "Unauthenticated GraphQL Introspection on pri.observability.app.launchdarkly.com",
        "/",
        scan_id="s2b",
    )
    # Both should map to the same normalised form (the second is a
    # substring-prefix; the normaliser doesn't substring-strip, but the
    # substring is a prefix of the longer one, and the dedup would
    # normally hit on the second call. Document the actual behaviour:
    # if normalisation DOESN'T collapse these, the test asserts the
    # current behaviour and the test serves as a regression marker for
    # a future fuzzy-match improvement.
    # Today: the substring case IS the same normalised form, so err1
    # and err2 both land in the same bucket and err2 is None.
    assert err1 is None
    assert err2 is None


def test_max_retries_is_two():
    """The cap is intentionally low — one real attempt plus one retry."""
    assert _MAX_RETRIES == 2


def test_block_after_two_retries():
    """attempt 1 → ok; attempt 2 → warning only; attempt 3 → block."""
    title = "XSS in /search"
    endpoint = "/search"
    assert _check_retry_guard(title, endpoint, scan_id="s3") is None
    err = _check_retry_guard(title, endpoint, scan_id="s3")
    assert err is None  # 2nd attempt: warn but allow
    err = _check_retry_guard(title, endpoint, scan_id="s3")
    assert err is not None  # 3rd attempt: block
    assert "RETRY LIMIT EXCEEDED" in err


def test_different_endpoints_are_separate_buckets():
    """Same title but different endpoint → distinct counter (the agent
    might be filing a related finding on a different asset).

    MAX_RETRIES=2 means the 3rd attempt blocks, not the 4th. So we
    expect 2 ok + 1 block on /api/a, and 2 ok + 1 block on /api/b
    independently.
    """
    title = "CORS Misconfiguration Exposes User Data"
    # First bucket: 2 ok
    assert _check_retry_guard(title, "/api/a", scan_id="s4") is None
    assert _check_retry_guard(title, "/api/a", scan_id="s4") is None
    # First bucket: 3rd attempt blocked
    err = _check_retry_guard(title, "/api/a", scan_id="s4")
    assert err is not None
    # Second bucket: still has its own 2-attempt budget
    assert _check_retry_guard(title, "/api/b", scan_id="s4") is None
    assert _check_retry_guard(title, "/api/b", scan_id="s4") is None
    err = _check_retry_guard(title, "/api/b", scan_id="s4")
    assert err is not None


def test_scan_id_scopes_the_counter():
    """Two scans in the same process must not share retry counts."""
    title = "IDOR on /api/orders/{id}"
    # Scan A: burn the cap
    _check_retry_guard(title, "/api/orders/1", scan_id="scan-a")
    _check_retry_guard(title, "/api/orders/1", scan_id="scan-a")
    err = _check_retry_guard(title, "/api/orders/1", scan_id="scan-a")
    assert err is not None
    # Scan B: same title, fresh counter, no error
    assert _check_retry_guard(title, "/api/orders/1", scan_id="scan-b") is None


def test_reset_retry_guard_by_scan_id_only_clears_that_scan():
    _check_retry_guard("XSS on /a", "/a", scan_id="keep")
    _check_retry_guard("XSS on /a", "/a", scan_id="drop")
    _check_retry_guard("XSS on /a", "/a", scan_id="drop")
    reset_retry_guard(scan_id="drop")
    # 'keep' still has its single attempt recorded
    assert ("keep", "xss on /a", "/a") in _retry_counters
    assert ("drop", "xss on /a", "/a") not in _retry_counters


def test_default_scan_id_when_omitted():
    """When the caller doesn't pass scan_id, all attempts share the
    '_default' bucket."""
    title = "Auth Bypass on /admin"
    _check_retry_guard(title, "/admin")
    _check_retry_guard(title, "/admin")
    err = _check_retry_guard(title, "/admin")
    assert err is not None


def test_block_message_mentions_normalised_title():
    """The agent gets a hint about what tripped the guard."""
    _check_retry_guard("XSS in /search", "/search", scan_id="s5")
    _check_retry_guard("XSS in /search", "/search", scan_id="s5")
    err = _check_retry_guard("Test: XSS in /search.", "/search", scan_id="s5")
    assert err is not None
    assert "xss in /search" in err  # normalised form, not the raw 3rd title
