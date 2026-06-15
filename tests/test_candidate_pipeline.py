from __future__ import annotations

import sqlite3

import pytest

from prometheus.core.candidate_store import CandidateStore
from prometheus.core.report_artifacts import generate_submission_artifacts
from prometheus.core.validation_gates import evaluate_validation_gate
from prometheus.db.migrations import apply_prometheus_migrations
from prometheus.tools.knowledge.store import KnowledgeStore


def test_migration_preserves_existing_rows_and_backfills_candidates(tmp_path) -> None:
    db = tmp_path / "prometheus.db"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE programs(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE targets(id TEXT PRIMARY KEY, domain TEXT);
        CREATE TABLE scans(scan_id TEXT PRIMARY KEY);
        CREATE TABLE scan_history(id INTEGER PRIMARY KEY, domain TEXT, scan_id TEXT);
        CREATE TABLE report_status(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            finding_title TEXT NOT NULL,
            finding_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            severity TEXT,
            cvss REAL,
            endpoint TEXT,
            cwe TEXT,
            platform TEXT,
            report_url TEXT,
            h1_report_id TEXT,
            notes TEXT,
            submitted_at TEXT,
            resolved_at TEXT,
            last_verified_at TEXT,
            full_finding_json TEXT,
            active_h1_version INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(domain, finding_hash)
        );
        CREATE TABLE knowledge(id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, category TEXT, key TEXT, value TEXT, confidence REAL, source TEXT, created_at TEXT, updated_at TEXT, scan_id TEXT);
        CREATE TABLE finding_comments(id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER, comment_type TEXT, content TEXT, created_at TEXT, version INTEGER);
        CREATE TABLE target_profiles(domain TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT);
        INSERT INTO programs(name) VALUES ('Tesla');
        INSERT INTO targets(id, domain) VALUES ('t1', 'example.com');
        INSERT INTO scans(scan_id) VALUES ('scan-1');
        INSERT INTO scan_history(domain, scan_id) VALUES ('example.com', 'scan-1');
        INSERT INTO report_status(domain, scan_id, finding_title, finding_hash, status, severity, endpoint, created_at, updated_at, full_finding_json)
        VALUES ('example.com', 'scan-1', 'IDOR exposes records', 'hash-1', 'new', 'high', '/api/records/1', '2026-06-03T00:00:00+00:00', '2026-06-03T00:00:00+00:00', '{"method":"GET","vuln_type":"idor"}');
        """
    )
    conn.commit()

    applied = apply_prometheus_migrations(conn)

    # Migration 003 is also applied; the new test in test_external_dedup
    # exercises the backfill behavior. The pre-migration candidate rows
    # are still preserved through the new migration.
    assert applied == [1, 2, 3]
    assert conn.execute("SELECT COUNT(*) FROM programs").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM report_status").fetchone()[0] == 1
    candidate = conn.execute("SELECT * FROM finding_candidates").fetchone()
    assert candidate["domain"] == "example.com"
    assert candidate["fingerprint"] == "hash-1"
    assert candidate["lifecycle_status"] == "needs_review"


def test_candidate_ingest_dedupes_and_rejects_junk(tmp_path) -> None:
    db = tmp_path / "prometheus.db"
    KnowledgeStore(db)
    store = CandidateStore(db)
    raw = {"title": "Missing X Frame Options header", "endpoint": "/", "severity": "low"}

    first = store.ingest_raw_finding(raw, domain="https://example.com", scan_id="scan-1")
    second = store.ingest_raw_finding(raw, domain="https://example.com", scan_id="scan-2")

    assert first["action"] == "created"
    assert second["action"] == "updated"
    rows = store.list_candidates(domain="example.com")
    assert len(rows) == 1
    assert rows[0]["lifecycle_status"] == "rejected"
    assert "missing security header" in rows[0]["rejection_reason"]


def test_ready_to_submit_requires_evidence_and_successful_validation(tmp_path) -> None:
    db = tmp_path / "prometheus.db"
    KnowledgeStore(db)
    store = CandidateStore(db)
    result = store.ingest_raw_finding(
        {
            "title": "IDOR exposes another user record",
            "endpoint": "/api/records/1",
            "vuln_type": "idor",
        },
        domain="example.com",
        scan_id="scan-1",
    )
    candidate_id = result["id"]

    with pytest.raises(ValueError, match="stored evidence"):
        store.transition_status(candidate_id, "validating")
        store.transition_status(candidate_id, "verified")
        store.transition_status(candidate_id, "ready_to_submit")

    store.add_evidence(
        finding_id=candidate_id,
        evidence_kind="control",
        summary="positive control unauthorized read",
    )
    store.record_validation_run(
        finding_id=candidate_id, validator="manual_review", status="success", output={"ok": True}
    )
    store.transition_status(candidate_id, "ready_to_submit")

    assert store.get_candidate(candidate_id)["lifecycle_status"] == "ready_to_submit"


def test_validation_gate_requires_controls_and_successful_run() -> None:
    evidence = [
        {"evidence_kind": "control", "summary": "positive control unauthorized read other user"},
        {"evidence_kind": "control", "summary": "positive control unauthorized read cross tenant"},
        {"evidence_kind": "control", "summary": "negative control expected denial"},
    ]
    runs = [{"validator": "manual_review", "status": "success"}]

    result = evaluate_validation_gate(vuln_type="idor", evidence=evidence, validation_runs=runs)

    assert result["passed"] is True
    assert result["positive_controls"] == 2
    assert result["negative_controls"] == 1


def test_report_artifacts_are_versioned_from_stored_evidence(tmp_path) -> None:
    db = tmp_path / "prometheus.db"
    KnowledgeStore(db)
    store = CandidateStore(db)
    result = store.ingest_raw_finding(
        {
            "title": "Auth bypass exposes admin panel",
            "endpoint": "https://example.com/admin",
            "vuln_type": "auth_bypass",
            "severity": "high",
        },
        domain="example.com",
        scan_id="scan-1",
    )
    candidate_id = result["id"]
    store.add_evidence(
        finding_id=candidate_id, evidence_kind="request", summary="GET /admin without auth"
    )
    store.add_evidence(
        finding_id=candidate_id, evidence_kind="response", summary="HTTP 200 admin data returned"
    )
    store.record_validation_run(
        finding_id=candidate_id,
        validator="manual_review",
        status="success",
        output={"verified": True},
    )

    artifacts = generate_submission_artifacts(
        candidate_id, platform="hackerone", artifact_root=tmp_path / "artifacts", db_path=db
    )

    assert artifacts["success"] is True
    assert len(artifacts["artifacts"]) == 4
    paths = [item["path"] for item in artifacts["artifacts"]]
    assert any(path.endswith("report.md") for path in paths)
    assert any(path.endswith("evidence_bundle.json") for path in paths)
    assert store.list_artifacts(candidate_id)


def test_outcome_feedback_rejects_similar_future_candidates(tmp_path) -> None:
    db = tmp_path / "prometheus.db"
    KnowledgeStore(db)
    store = CandidateStore(db)
    result = store.ingest_raw_finding(
        {"title": "CORS reflected origin", "endpoint": "/api/public", "vuln_type": "cors"},
        domain="example.com",
        scan_id="scan-1",
    )
    candidate_id = result["id"]
    store.transition_status(candidate_id, "validating")
    store.transition_status(candidate_id, "rejected", reason="No readable protected data")
    store.record_submission_outcome(
        finding_id=candidate_id, outcome="rejected", comments="No readable protected data"
    )

    future = store.ingest_raw_finding(
        {"title": "CORS reflected origin again", "endpoint": "/api/public", "vuln_type": "cors"},
        domain="example.com",
        scan_id="scan-2",
    )

    assert future["candidate"]["lifecycle_status"] == "rejected"
    assert "No readable protected data" in future["candidate"]["rejection_reason"]
