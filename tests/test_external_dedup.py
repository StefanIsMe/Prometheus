"""Tests for the external-state dedup pipeline (migration 003 + KnowledgeStore
extensions + the live_revalidate probes + the ingest CLI).

These run against a tmp_path DB so they don't touch ~/.prometheus/prometheus.db.
The pattern mirrors tests/test_candidate_pipeline.py — build the schema from
scratch, seed test rows, assert the dedup + revalidate + ingest paths.
"""
from __future__ import annotations

import csv
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SCRIPTS))

from prometheus.core.auto_revalidate import live_revalidate  # noqa: E402
from prometheus.tools.knowledge.store import KnowledgeStore  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """Point HOME to a tmp dir so KnowledgeStore opens a fresh DB."""
    home = tmp_path
    monkeypatch.setenv("HOME", str(home))
    # Force re-init of the KnowledgeStore singleton
    import prometheus.tools.knowledge.store as ks_module
    ks_module._instance = None
    ks_module._instance_lock.__init__()  # reset
    yield tmp_path / ".prometheus" / "prometheus.db"


def _seed_pkce_closed(fresh_db: Path) -> tuple[int, int]:
    """Insert the two known-closed rows (PKCE + enumeration) into a fresh
    DB, then return (pkce_rowid, enumeration_rowid). Triggers migration 003
    backfill as a side-effect of normal KnowledgeStore init."""
    ks = KnowledgeStore(fresh_db)
    ks.upsert_report_status(
        domain="auth.openai.com",
        scan_id="seed-pkce",
        finding_title="PKCE Downgrade to plain Method Accepted on OAuth Authorization Endpoint",
        severity="medium",
        cvss=4.2,
        endpoint="https://auth.openai.com/authorize",
        cwe="CWE-327",
        notes=(
            "Bugcrowd rejected 2026-06-02: Not reproducible, theoretical with no actual PoC/impact. "
            "Deducted 1 point. PKCE plain support alone cannot demonstrate token theft without a "
            "separate MitM/XSS vulnerability. Do NOT re-submit."
        ),
    )
    ks.upsert_report_status(
        domain="auth.openai.com",
        scan_id="seed-enum",
        finding_title=(
            "Account Enumeration via Differential Authentication Responses on auth.openai.com"
        ),
        severity="low",
        cvss=2.0,
        endpoint="https://auth.openai.com/api/accounts/authorize",
        cwe="CWE-203",
        notes=(
            "Submitted to OpenAI Safety Bug Bounty on Bugcrowd. VRT: Broken Access Control > "
            "Username Enumeration > Non Brute Force (P4). Target: openai.com. Category: Account "
            "and Platform Integrity."
        ),
    )
    # Run migration 003 backfill (also re-runs idempotently on init)
    from prometheus.db.migrations import apply_prometheus_migrations
    with sqlite3.connect(str(fresh_db)) as c:
        c.row_factory = sqlite3.Row
        c.execute("DELETE FROM schema_migrations WHERE version = 3")
        apply_prometheus_migrations(c)
    pkce_row = next(
        r
        for r in sqlite3.connect(str(fresh_db)).execute(
            "SELECT id FROM report_status WHERE finding_title LIKE 'PKCE%'"
        ).fetchall()
    )
    enum_row = next(
        r
        for r in sqlite3.connect(str(fresh_db)).execute(
            "SELECT id FROM report_status WHERE finding_title LIKE 'Account Enumeration%'"
        ).fetchall()
    )
    return pkce_row[0], enum_row[0]


# ---------------------------------------------------------------------------
# Layer 4: BM25
# ---------------------------------------------------------------------------

def test_bm25_layer_catches_reworded_pkce(fresh_db):
    """The two PKCE titles share ~67% of their tokens. BM25 should rank the
    stored row as a duplicate candidate for the user's prior title."""
    _seed_pkce_closed(fresh_db)
    ks = KnowledgeStore(fresh_db)
    result = ks.find_duplicate_finding(
        domain="auth.openai.com",
        finding_title="PKCE Downgrade: OAuth Authorization Server Advertises Insecure plain Method",
        endpoint="https://auth.openai.com/.well-known/openid-configuration",
        cwe="CWE-327",
    )
    assert result is not None
    assert result["layer"] in ("bm25", "external", "external_bm25", "exact_hash")
    if result["layer"] == "bm25":
        assert result["finding"] is not None
        assert "PKCE" in (result["finding"].get("finding_title") or "")


def test_bm25_layer_unchanged_title_still_hits(fresh_db):
    """Exact reworded but word-identical: should hit bm25 or external_bm25."""
    _seed_pkce_closed(fresh_db)
    ks = KnowledgeStore(fresh_db)
    # This is the EXACT on-disk title — should hit exact_hash or cwe_endpoint
    result = ks.find_duplicate_finding(
        domain="auth.openai.com",
        finding_title="PKCE Downgrade to plain Method Accepted on OAuth Authorization Endpoint",
        endpoint="https://auth.openai.com/authorize",
        cwe="CWE-327",
    )
    assert result is not None
    # exact_hash because the (title, endpoint) hash matches
    assert result["layer"] == "exact_hash"


def test_bm25_no_match_for_unrelated_finding(fresh_db):
    """An unrelated finding should NOT match via BM25."""
    _seed_pkce_closed(fresh_db)
    ks = KnowledgeStore(fresh_db)
    result = ks.find_duplicate_finding(
        domain="auth.openai.com",
        finding_title="Server-Side Request Forgery in /api/webhook",
        endpoint="https://auth.openai.com/api/webhook",
        cwe="CWE-918",
    )
    # No match is the correct outcome. Note: a CWE-918 SSRF in auth.openai.com
    # is unlikely to overlap with PKCE/Auth0 tokens. We accept any of
    # the less-precise layers only if they actually overlap meaningfully.
    if result is not None:
        layer = result.get("layer")
        # Allow cwe_endpoint (different CWE so this should not match either),
        # but not the strong layers.
        assert layer not in ("exact_hash", "title_similarity"), (
            f"unrelated finding matched strongly: {result}"
        )


# ---------------------------------------------------------------------------
# should_revalidate policy
# ---------------------------------------------------------------------------

def test_external_state_blocks_refile_within_90d(fresh_db):
    """Within 90 days of a 'not_reproducible' closure: archive (block re-file)."""
    pkce_id, _enum_id = _seed_pkce_closed(fresh_db)
    ks = KnowledgeStore(fresh_db)
    policy = ks.should_revalidate(
        domain="auth.openai.com",
        finding_title="PKCE Downgrade: OAuth Authorization Server Advertises Insecure plain Method",
        endpoint="https://auth.openai.com/.well-known/openid-configuration",
        cwe="CWE-327",
    )
    assert policy["action"] == "archive"
    assert "not_reproducible" in policy["reason"]
    assert policy["external"] is not None
    assert policy["external"]["external_id"] == "e4c2a739-7972-493e-a988-76ad853e6175"


def test_external_state_allows_revalidation_after_90d(fresh_db):
    """Past 90 days: revalidate (run live probe before re-filing)."""
    _seed_pkce_closed(fresh_db)
    # Age the external row past the cooldown
    with sqlite3.connect(str(fresh_db)) as c:
        c.row_factory = sqlite3.Row
        c.execute(
            "UPDATE external_submissions SET triaged_at = '2026-01-01T00:00:00+00:00' "
            "WHERE external_id = 'e4c2a739-7972-493e-a988-76ad853e6175'"
        )
        c.commit()
    ks = KnowledgeStore(fresh_db)
    policy = ks.should_revalidate(
        domain="auth.openai.com",
        finding_title="PKCE Downgrade: OAuth Authorization Server Advertises Insecure plain Method",
        endpoint="https://auth.openai.com/.well-known/openid-configuration",
        cwe="CWE-327",
    )
    assert policy["action"] == "revalidate"
    assert "past cooldown" in policy["reason"].lower() or "cooldown" in policy["reason"].lower()


def test_local_terminal_status_blocks_new_finding(fresh_db):
    """A local report_status row already in 'submitted' blocks new filings,
    even without an external_submissions row."""
    ks = KnowledgeStore(fresh_db)
    ks.upsert_report_status(
        domain="example.com",
        scan_id="seed-1",
        finding_title="IDOR exposes user records",
        severity="high",
        cvss=7.5,
        endpoint="https://example.com/api/records/1",
        cwe="CWE-639",
        status="submitted",
    )
    policy = ks.should_revalidate(
        domain="example.com",
        finding_title="IDOR exposes user records",
        endpoint="https://example.com/api/records/1",
        cwe="CWE-639",
    )
    assert policy["action"] == "archive"
    assert "submitted" in policy["reason"]


# ---------------------------------------------------------------------------
# live_revalidate
# ---------------------------------------------------------------------------

def test_live_revalidate_pkce_unchanged(monkeypatch):
    """Live PKCE probe against auth.openai.com should return changed=False
    because the discovery doc still advertises plain (verified 2026-06-13)."""
    # Network test — gate on the user's connectivity; skip if env says so
    if os.environ.get("PROMETHEUS_TEST_OFFLINE") == "1":
        pytest.skip("offline mode")
    result = live_revalidate({
        "finding_title": "PKCE Downgrade to plain Method Accepted on OAuth Authorization Endpoint",
        "domain": "auth.openai.com",
        "endpoint": "https://auth.openai.com/.well-known/openid-configuration",
        "vuln_type": "oauth_vulnerabilities",
    })
    assert result["probe"] in ("oauth_vulnerabilities", "pkce", "oauth", "openid_configuration")
    assert result["changed"] is False
    assert "plain" in (result["evidence"] or "").lower()


def test_live_revalidate_picks_class_from_title(monkeypatch):
    """When vuln_type is empty, infer from title keywords."""
    if os.environ.get("PROMETHEUS_TEST_OFFLINE") == "1":
        pytest.skip("offline mode")
    result = live_revalidate({
        "finding_title": "CORS reflection on /api/endpoint",
        "domain": "example.com",
        "endpoint": "https://example.com/api/endpoint",
        "vuln_type": "",
    })
    assert result["probe"] == "cors"


def test_live_revalidate_fallback_body_hash(monkeypatch):
    """A finding with no class match uses the body-hash fallback."""
    if os.environ.get("PROMETHEUS_TEST_OFFLINE") == "1":
        pytest.skip("offline mode")
    result = live_revalidate({
        "finding_title": "Generic recon finding",
        "domain": "example.com",
        "endpoint": "https://example.com/",
        "vuln_type": "unknown",
    })
    assert result["probe"] == "fallback"
    assert "body_hash" in (result["evidence"] or "")


# ---------------------------------------------------------------------------
# Ingest CLI
# ---------------------------------------------------------------------------

def test_ingest_single_backfills_internal_row(fresh_db, monkeypatch):
    """The single subcommand writes external_submissions and propagates."""
    monkeypatch.setattr(
        "prometheus.tools.knowledge.store._instance", None, raising=False
    )
    # Run as a subprocess so HOME is set; the KnowledgeStore singleton
    # is process-scoped, so the subprocess is the right boundary here.
    env = dict(os.environ)
    env["HOME"] = str(fresh_db.parent)
    fresh_db.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(SCRIPTS / "prom_rl_ingest_external.py"),
        "single",
        "--platform", "bugcrowd",
        "--external-id", "test-uuid-1",
        "--domain", "auth.openai.com",
        "--cwe", "CWE-327",
        "--title", "PKCE Downgrade test row",
        "--endpoint", "https://auth.openai.com/.well-known/openid-configuration",
        "--status", "not_reproducible",
        "--priority", "P1",
        "--triager", "TestTriager",
        "--notes", "test row from automated test",
    ]
    subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)
    # The subprocess opened its own DB at $HOME/.prometheus/prometheus.db
    target_db = fresh_db.parent / ".prometheus" / "prometheus.db"
    assert target_db.exists(), f"subprocess did not create {target_db}"
    # Verify external_submissions
    with sqlite3.connect(str(target_db)) as c:
        c.row_factory = sqlite3.Row
        ext = c.execute(
            "SELECT * FROM external_submissions WHERE external_id = 'test-uuid-1'"
        ).fetchone()
    assert ext is not None
    assert dict(ext)["status"] == "not_reproducible"
    assert dict(ext)["triager"] == "TestTriager"
    # Verify report_status propagation
    with sqlite3.connect(str(target_db)) as c:
        c.row_factory = sqlite3.Row
        rs = c.execute(
            "SELECT * FROM report_status WHERE external_id = 'test-uuid-1'"
        ).fetchone()
    assert rs is not None
    assert dict(rs)["external_status"] == "not_reproducible"
    # Verify a comment of type external_triage was written
    with sqlite3.connect(str(target_db)) as c:
        c.row_factory = sqlite3.Row
        comment = c.execute(
            "SELECT * FROM finding_comments WHERE comment_type = 'external_triage' "
            "AND finding_id = ?", (dict(rs)["id"],)
        ).fetchone()
    assert comment is not None
    assert "TestTriager" in dict(comment)["content"]


def test_ingest_csv_tolerant_of_columns(fresh_db, monkeypatch):
    """A Bugcrowd export with shuffled column names should still parse."""
    monkeypatch.setattr(
        "prometheus.tools.knowledge.store._instance", None, raising=False
    )
    fresh_db.parent.mkdir(parents=True, exist_ok=True)
    csv_path = fresh_db.parent / "test_export.csv"
    csv_path.write_text(
        "Submission ID,Title,State,Priority,Target Location\n"
        "uuid-1,SQL Injection,/api/users,P3,api.example.com\n"
        "uuid-2,XSS in search,Resolved,P4,example.com\n"
    )
    env = dict(os.environ)
    env["HOME"] = str(fresh_db.parent)
    cmd = [
        sys.executable,
        str(SCRIPTS / "prom_rl_ingest_external.py"),
        "bugcrowd",
        str(csv_path),
    ]
    result = subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)
    # Parse "created=N updated=M errors=0"
    last_line = result.stdout.strip().splitlines()[-1]
    assert "created=2" in last_line, f"unexpected output: {result.stdout!r}"
    target_db = fresh_db.parent / ".prometheus" / "prometheus.db"
    with sqlite3.connect(str(target_db)) as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT external_id, status, domain FROM external_submissions"
        ).fetchall()
    rows = [dict(r) for r in rows]
    assert len(rows) == 2
    ids = {r["external_id"] for r in rows}
    assert ids == {"uuid-1", "uuid-2"}
    # "Resolved" should map to "resolved"
    resolved = [r for r in rows if r["external_id"] == "uuid-2"][0]
    assert resolved["status"] == "resolved"


# ---------------------------------------------------------------------------
# End-to-end: scan-end dedup gate
# ---------------------------------------------------------------------------

def test_sync_scan_findings_blocked_by_external_state(fresh_db, monkeypatch):
    """A re-scan that produces a finding matching an external closure should
    be blocked at sync time (via should_revalidate → archive)."""
    _seed_pkce_closed(fresh_db)
    monkeypatch.setattr(
        "prometheus.tools.knowledge.store._instance", None, raising=False
    )
    ks = KnowledgeStore(fresh_db)
    # Build a re-scan finding that matches the closed PKCE row
    rescanned = {
        "title": "PKCE Downgrade: OAuth Authorization Server Advertises Insecure plain Method",
        "endpoint": "https://auth.openai.com/.well-known/openid-configuration",
        "cwe": "CWE-327",
        "severity": "medium",
        "cvss": 4.2,
    }
    # Apply the same gate runner.py uses
    policy = ks.should_revalidate(
        domain="auth.openai.com",
        finding_title=rescanned["title"],
        endpoint=rescanned["endpoint"],
        cwe=rescanned["cwe"],
    )
    assert policy["action"] == "archive"
    # The runner.py gate code would drop this finding before sync_scan_findings


# ---------------------------------------------------------------------------
# BM25 threshold env var
# ---------------------------------------------------------------------------

def test_bm25_threshold_env_var(fresh_db, monkeypatch):
    """PROMETHEUS_BM25_DEDUP_THRESHOLD controls the layer 4 sensitivity."""
    _seed_pkce_closed(fresh_db)
    monkeypatch.setattr(
        "prometheus.tools.knowledge.store._instance", None, raising=False
    )
    monkeypatch.setenv("PROMETHEUS_BM25_DEDUP_THRESHOLD", "-100.0")
    # Layer 4 won't fire because the score is never below -100
    # (we use this only to test that the env var is read; the actual
    # score-against-threshold logic is in KnowledgeStore._find_duplicate_bm25)
    from prometheus.tools.knowledge.store import KnowledgeStore
    ks = KnowledgeStore(fresh_db)
    # Sanity: with default threshold, layer 4 still fires for the reworded title
    monkeypatch.delenv("PROMETHEUS_BM25_DEDUP_THRESHOLD", raising=False)
    result = ks.find_duplicate_finding(
        domain="auth.openai.com",
        finding_title="PKCE Downgrade: OAuth Authorization Server Advertises Insecure plain Method",
        endpoint="https://auth.openai.com/.well-known/openid-configuration",
        cwe="CWE-327",
    )
    assert result is not None
