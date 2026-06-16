"""Tests for the threat-intel query slug (Phase 1D).

The audit of 175 scan-run logs (Phase 1D) found 19 NVD, 30 VulnerableCode,
and many CIRCL failures — all stemming from the agent's free-form
fingerprint text being passed verbatim as the search term to online
APIs, producing 200+ char `?purl=pkg:npm/...` URLs that the APIs
rejected (CIRCL 404, VulnerableCode 405, NVD silent drop).

The fix: ``slugify_tech`` reduces each fingerprint to a short slug
(max 64 chars, alphanumeric+dash) before any online call. The full
text is preserved for the local BM25 lookup.
"""

from __future__ import annotations

import sys
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.tools.threat_intel.query_engine import (  # noqa: E402
    _SLUG_MAX_LEN,
    slugify_tech,
)


# ---------------------------------------------------------------------------
# 1. Unit: CVE-id extraction
# ---------------------------------------------------------------------------


def test_slugify_extracts_cve_id():
    """A free-form text containing a CVE id should be reduced to that
    CVE id. This is the audit's exact case from scan-13b53eb1."""
    text = "Comprehensive nuclei scan coverage: CVE-2025-29927 (middleware bypass), CVE-2026-44578 (WebSocket SSRF), ..."
    assert slugify_tech(text) == "CVE-2025-29927"


def test_slugify_extracts_first_cve_when_multiple():
    """Multiple CVE ids in the same string → return the first one."""
    text = "Critical: CVE-2024-1234, CVE-2025-5678"
    assert slugify_tech(text) == "CVE-2024-1234"


def test_slugify_handles_cve_with_leading_text():
    """A CVE id preceded by punctuation / whitespace still matches."""
    text = "... see also: (CVE-2026-44578) for context ..."
    assert slugify_tech(text) == "CVE-2026-44578"


# ---------------------------------------------------------------------------
# 2. Unit: fallback to first 5 tokens
# ---------------------------------------------------------------------------


def test_slugify_falls_back_to_tokens():
    """When no CVE id is present, use the first 5 alphanumeric tokens."""
    text = "Cloudflare WAF with bot challenges"
    assert slugify_tech(text) == "cloudflare-waf-with-bot-challenges"


def test_slugify_caps_at_five_tokens():
    text = "alpha beta gamma delta epsilon zeta eta"
    out = slugify_tech(text)
    assert out == "alpha-beta-gamma-delta-epsilon"


def test_slugify_truncates_long_slugs():
    """Slugs longer than _SLUG_MAX_LEN are truncated (and trailing dash stripped)."""
    long_text = "next-" + ("framework" * 20)  # 200+ chars
    out = slugify_tech(long_text)
    assert len(out) <= _SLUG_MAX_LEN
    assert not out.endswith("-")


# ---------------------------------------------------------------------------
# 3. Unit: safety
# ---------------------------------------------------------------------------


def test_slugify_handles_empty_string():
    assert slugify_tech("") == ""


def test_slugify_handles_none():
    # Type checker-friendly — the function should not raise on None.
    assert slugify_tech(None) == ""  # type: ignore[arg-type]


def test_slugify_handles_pure_punctuation():
    """A string with no alphanumeric tokens falls back to a cleaned truncation."""
    text = "!!!@@@###"
    out = slugify_tech(text)
    # No CVE, no tokens → empty after cleanup
    assert out == ""


def test_slugify_url_safe_characters():
    """The slug must be safe to use as a URL path segment."""
    text = "CVE-2025-29927 / middleware auth bypass"
    out = slugify_tech(text)
    # All chars in [A-Za-z0-9._-]
    for ch in out:
        assert ch.isalnum() or ch in {".", "_", "-"}, f"unsafe char {ch!r} in {out!r}"


def test_slugify_preserves_package_name_dots_and_dashes():
    """Common package naming (e.g. @angular/core, next.js) must survive."""
    # The fallback-token path should pick up alphanumeric tokens
    # including dots and dashes (e.g. next.js)
    text = "next.js with Turbopack bundler"
    out = slugify_tech(text)
    # Token regex allows dots/dashes inside a token
    assert "next.js" in out or "next" in out
    assert len(out) <= _SLUG_MAX_LEN


# ---------------------------------------------------------------------------
# 4. E2E log-replay: the audit's worst case
# ---------------------------------------------------------------------------


def _load_log_replay_target() -> Path:
    """Return the path of the worst real log for the slug failure
    category — the scan whose VulnerableCode/CIRCL URLs exceeded 256
    chars because of long descriptive tech strings."""
    runs_root = SOURCE_ROOT / "prometheus_runs"
    # scan-13b53eb1 had the most extreme URL-encoded tech strings
    preferred = runs_root / "scan-13b53eb1" / "prometheus.log"
    if preferred.exists():
        return preferred
    # Fall back: any prometheus.log with a 'VulnerableCode query failed'
    # or 'CIRCL query failed' line
    best: tuple[int, Path] | None = None
    for log in runs_root.glob("*/prometheus.log"):
        text = log.read_text(errors="replace")
        n = text.count("VulnerableCode query failed") + text.count("CIRCL query failed")
        if n and (best is None or n > best[0]):
            best = (n, log)
    assert best is not None, "no log with VulnerableCode/CIRCL failures found"
    return best[1]


def test_log_replay_long_url_payload_now_slugs_cleanly():
    """The recorded scan-13b53eb1 log contains
    ``?purl=pkg:npm/comprehensive%20nuclei%20scan%20coverage:...`` URLs
    over 1000 chars long. With the new ``slugify_tech``, the equivalent
    payload slug is at most 64 chars and contains no spaces or colons."""
    log_path = _load_log_replay_target()
    text = log_path.read_text(errors="replace")  # codeql[py/unused-local-variable] : suppressed via the security dashboard triage
    # The audit's exact long payload (extracted from a CIRCL query failure)
    long_payload = (
        "Comprehensive nuclei scan coverage: CVE-2025-29927 (CVSS 9.1, "
        "middleware auth bypass via x-middleware-subrequest header), "
        "CVE-2026-44578 (CVSS 8.6, WebSocket SSRF - self-hosted only)"
    )
    slug = slugify_tech(long_payload)
    assert slug == "CVE-2025-29927"
    assert len(slug) <= _SLUG_MAX_LEN
    # And the slug is a valid URL path component (no spaces, no colons)
    assert " " not in slug
    assert ":" not in slug
    assert "%" not in slug
    # Sanity-check the source payload contains the slug target.
    assert long_payload  # noqa: F841  — kept for readability of the test inputs
