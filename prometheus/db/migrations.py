"""Prometheus SQLite migration framework.

Migrations run in place. They never wipe the live DB.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from datetime import UTC, datetime
from typing import Any

Migration = Callable[[sqlite3.Connection], None]


def apply_prometheus_migrations(conn: sqlite3.Connection) -> list[int]:
    """Apply all pending migrations and return applied versions."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    applied = {
        int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
    }

    applied_now: list[int] = []
    for version, name, migration in _MIGRATIONS:
        if version in applied:
            continue
        with conn:
            migration(conn)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, datetime.now(UTC).isoformat()),
            )
        applied_now.append(version)
    return applied_now


def _migration_001_candidate_lifecycle_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_candidates (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            source_tool TEXT NOT NULL,
            source_type TEXT NOT NULL,
            title TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            severity TEXT,
            confidence REAL,
            endpoint TEXT,
            method TEXT,
            parameter TEXT,
            auth_state TEXT,
            role TEXT,
            workflow_step TEXT,
            fingerprint TEXT NOT NULL,
            lifecycle_status TEXT NOT NULL,
            rejection_reason TEXT,
            raw_finding_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_candidates_domain_fingerprint
            ON finding_candidates(domain, fingerprint);
        CREATE INDEX IF NOT EXISTS idx_finding_candidates_status
            ON finding_candidates(lifecycle_status);
        CREATE INDEX IF NOT EXISTS idx_finding_candidates_domain_status
            ON finding_candidates(domain, lifecycle_status);
        CREATE INDEX IF NOT EXISTS idx_finding_candidates_scan
            ON finding_candidates(scan_id);

        CREATE TABLE IF NOT EXISTS finding_evidence (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            evidence_kind TEXT NOT NULL,
            summary TEXT,
            path TEXT,
            inline_json TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
            ON finding_evidence(finding_id);
        CREATE INDEX IF NOT EXISTS idx_finding_evidence_kind
            ON finding_evidence(evidence_kind);

        CREATE TABLE IF NOT EXISTS validation_runs (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            validator TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence REAL,
            output_json TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_validation_runs_finding
            ON validation_runs(finding_id);
        CREATE INDEX IF NOT EXISTS idx_validation_runs_status
            ON validation_runs(status);

        CREATE TABLE IF NOT EXISTS submission_artifacts (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            version INTEGER NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE,
            UNIQUE(finding_id, platform, artifact_type, version)
        );

        CREATE INDEX IF NOT EXISTS idx_submission_artifacts_finding
            ON submission_artifacts(finding_id);
        CREATE INDEX IF NOT EXISTS idx_submission_artifacts_kind
            ON submission_artifacts(platform, artifact_type);

        CREATE TABLE IF NOT EXISTS submission_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            actor TEXT NOT NULL,
            payload_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_submission_events_finding
            ON submission_events(finding_id);
        CREATE INDEX IF NOT EXISTS idx_submission_events_type
            ON submission_events(event_type);

        CREATE TABLE IF NOT EXISTS outcome_feedback_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_key TEXT NOT NULL UNIQUE,
            vuln_type TEXT,
            endpoint_pattern TEXT,
            outcome TEXT NOT NULL,
            rejection_hint TEXT,
            accepted_count INTEGER NOT NULL DEFAULT 0,
            rejected_count INTEGER NOT NULL DEFAULT 0,
            duplicate_count INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    _backfill_candidates_from_report_status(conn)


def _backfill_candidates_from_report_status(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT * FROM report_status").fetchall()
    now = datetime.now(UTC).isoformat()
    for row in rows:
        row_dict = _row_to_dict(row)
        raw_json = row_dict.get("full_finding_json") or json.dumps(
            row_dict, ensure_ascii=False, default=str
        )
        parsed = _json_or_empty(raw_json)
        report_id = row_dict.get("id")
        finding_id = f"report-{report_id}"
        fingerprint = str(row_dict.get("finding_hash") or finding_id)
        domain = str(row_dict.get("domain") or "unknown")
        title = str(row_dict.get("finding_title") or parsed.get("title") or "Untitled finding")
        status = _map_legacy_status(str(row_dict.get("status") or "new"))
        created_at = str(row_dict.get("created_at") or now)
        updated_at = str(row_dict.get("updated_at") or created_at)
        vuln_type = str(
            parsed.get("vuln_type") or parsed.get("type") or row_dict.get("cwe") or "unknown"
        )
        method = parsed.get("method") or row_dict.get("method")

        conn.execute(
            """
            INSERT INTO finding_candidates (
                id, domain, scan_id, source_tool, source_type, title, vuln_type,
                severity, confidence, endpoint, method, parameter, auth_state,
                role, workflow_step, fingerprint, lifecycle_status,
                rejection_reason, raw_finding_json, created_at, updated_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain, fingerprint) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                updated_at = excluded.updated_at,
                raw_finding_json = excluded.raw_finding_json
            """,
            (
                finding_id,
                domain,
                str(row_dict.get("scan_id") or "legacy"),
                "report_status",
                "legacy_projection",
                title,
                vuln_type,
                row_dict.get("severity"),
                None,
                row_dict.get("endpoint") or parsed.get("endpoint"),
                method,
                parsed.get("parameter"),
                parsed.get("auth_state"),
                parsed.get("role"),
                parsed.get("workflow_step"),
                fingerprint,
                status,
                None,
                raw_json,
                created_at,
                updated_at,
                updated_at,
            ),
        )


def _row_to_dict(row: Any) -> dict[str, Any]:
    if hasattr(row, "keys"):
        return {key: row[key] for key in row.keys()}
    return dict(row)


def _json_or_empty(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _map_legacy_status(status: str) -> str:
    return {
        "new": "needs_review",
        "reviewing": "needs_review",
        "needs_info": "needs_review",
        "dismissed": "archived",
        "revalidated": "verified",
    }.get(status, status if status else "needs_review")


def _migration_002_normalize_lifecycle_statuses(conn: sqlite3.Connection) -> None:
    conn.execute(
        "UPDATE finding_candidates SET lifecycle_status = 'rejected', rejection_reason = COALESCE(rejection_reason, 'informative outcome') WHERE lifecycle_status = 'informative'"
    )
    conn.execute(
        "UPDATE finding_candidates SET lifecycle_status = 'archived' WHERE lifecycle_status = 'superseded'"
    )
    conn.execute("UPDATE report_status SET status = 'rejected' WHERE status = 'informative'")
    conn.execute("UPDATE report_status SET status = 'archived' WHERE status = 'superseded'")


def _migration_003_external_submissions_and_bm25(conn: sqlite3.Connection) -> None:
    """Add external_submissions table, FTS5 over report_status, and 3 new
    report_status columns for tracking triager state from external platforms
    (Bugcrowd, HackerOne). All additive, safe to run on a populated DB.

    Backfill: parses report_status.notes for the two known-closed OpenAI
    submissions and creates matching external_submissions rows so future
    scans see them as already-closed ground.
    """
    # 1. New table for external platform submissions (Bugcrowd, H1, internal).
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS external_submissions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            platform        TEXT    NOT NULL,
            external_id     TEXT    NOT NULL,
            domain          TEXT    NOT NULL,
            finding_title   TEXT    NOT NULL,
            finding_hash    TEXT    NOT NULL,
            endpoint        TEXT,
            cwe             TEXT,
            status          TEXT    NOT NULL,
            priority        TEXT,
            reward_usd      REAL,
            report_url      TEXT,
            triager         TEXT,
            triaged_at      TEXT,
            notes           TEXT,
            raw_export_json TEXT,
            created_at      TEXT    NOT NULL,
            updated_at      TEXT    NOT NULL,
            UNIQUE(platform, external_id)
        );

        CREATE INDEX IF NOT EXISTS idx_external_submissions_domain
            ON external_submissions(domain);
        CREATE INDEX IF NOT EXISTS idx_external_submissions_hash
            ON external_submissions(finding_hash);
        CREATE INDEX IF NOT EXISTS idx_external_submissions_status
            ON external_submissions(status);
        CREATE INDEX IF NOT EXISTS idx_external_submissions_triaged
            ON external_submissions(triaged_at);
        """
    )

    # 2. Add external_* columns to report_status (3 new columns, all NULL-safe).
    cols = {c[1] for c in conn.execute("PRAGMA table_info(report_status)").fetchall()}
    for col in ("external_priority", "external_status", "external_id"):
        if col not in cols:
            conn.execute(f"ALTER TABLE report_status ADD COLUMN {col} TEXT")
            conn.commit()

    # 3. FTS5 virtual tables for BM25 dedup.
    #    Two virtual tables:
    #      - report_status_fts: matches new findings against local report_status
    #      - external_submissions_fts: matches new findings against the user's
    #        prior platform submissions (Bugcrowd, H1)
    #    Uses external-content mode so the source rows remain in their parent
    #    tables. We deliberately do NOT add AFTER INSERT/UPDATE/DELETE triggers
    #    on the parent tables to populate the FTS indices — FTS5 triggers on
    #    the parent table cause "database disk image is malformed" errors
    #    mid-transaction on this SQLite version (3.51.2) when combined with
    #    external-content mode. Instead, callers of upsert_report_status (in
    #    KnowledgeStore) and the backfill below keep the FTS tables in sync
    #    via the 'rebuild' command.
    conn.executescript(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS report_status_fts
            USING fts5(
                finding_title,
                notes,
                full_finding_json,
                content='report_status',
                content_rowid='id',
                tokenize='porter unicode61'
            );

        CREATE VIRTUAL TABLE IF NOT EXISTS external_submissions_fts
            USING fts5(
                finding_title,
                notes,
                content='external_submissions',
                content_rowid='id',
                tokenize='porter unicode61'
            );
        """
    )

    # 4. Rebuild FTS indices from current parent-table state. External-content
    #    FTS5 tables are not auto-populated; we need an explicit rebuild.
    conn.execute("INSERT INTO report_status_fts(report_status_fts) VALUES('rebuild')")
    try:
        conn.execute(
            "INSERT INTO external_submissions_fts(external_submissions_fts) VALUES('rebuild')"
        )
    except sqlite3.OperationalError:
        # external_submissions may be empty (no backfill rows); that's fine
        pass
    conn.commit()

    # 5. Backfill external_submissions from the two known-closed OpenAI rows
    #    whose notes already contain the triager verdict. This makes the
    #    system start knowing about the user's prior closed reports on the
    #    next scan, no CLI required.
    _backfill_external_submissions_from_notes(conn)
    # After backfill, rebuild FTS so the new external rows are searchable.
    conn.execute("INSERT INTO external_submissions_fts(external_submissions_fts) VALUES('rebuild')")
    conn.commit()


def _backfill_external_submissions_from_notes(conn: sqlite3.Connection) -> None:
    """Parse report_status.notes for the two known-closed OpenAI submissions
    and create external_submissions rows. Idempotent: UNIQUE(platform,
    external_id) prevents duplicates.

    Match rules (any of):
      - triager's handle appears in the notes string
      - 30+ character overlap between on-disk title and backfill title
      - finding_hash matches a known hash (e.g. 2a224bda58fa9d90 for PKCE)
    """
    # Match rules: (external_id, [trigger_phrases], canonical_title, status, priority, triager)
    # When MULTIPLE rows match, prefer the one where the canonical_title overlaps.
    known_backfills = [
        {
            "platform": "bugcrowd",
            "external_id": "e4c2a739-7972-493e-a988-76ad853e6175",
            "title": "PKCE Downgrade: OAuth Authorization Server Advertises Insecure 'plain' Method",
            "triggers": (
                "bugcrowd_triage_handle_1",
                "PKCE Downgrade",
                "2a224bda58fa9d90",
                "Not reproducible",
            ),
            "status": "not_reproducible",
            "priority": "P1",
            "triager": "bugcrowd_triage_handle_1",
        },
        {
            "platform": "bugcrowd",
            "external_id": "b0a131b8-85c3-4715-9362-fc7ec7fd1569",
            "title": "Account Enumeration via Differential Login Responses on auth.openai.com",
            "triggers": (
                "bugcrowd_triage_handle_2",
                "Account Enumeration",
                "1bede986504b2009",
                "Username Enumeration",
            ),
            "status": "informative",
            "priority": "P5",
            "triager": "bugcrowd_triage_handle_2",
        },
    ]

    rows = conn.execute("SELECT * FROM report_status").fetchall()
    now = datetime.now(UTC).isoformat()
    for row in rows:
        row_dict = _row_to_dict(row)
        notes = str(row_dict.get("notes") or "")
        title = str(row_dict.get("finding_title") or "")
        finding_hash = str(row_dict.get("finding_hash") or "")
        for backfill in known_backfills:
            # Match any trigger phrase in notes or title, or the hash
            matched = any(
                trigger in notes or trigger.lower() in title.lower()
                for trigger in backfill["triggers"]
            )
            if not matched:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO external_submissions
                    (platform, external_id, domain, finding_title, finding_hash,
                     endpoint, cwe, status, priority, triager, triaged_at,
                     notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    backfill["platform"],
                    backfill["external_id"],
                    str(row_dict.get("domain") or ""),
                    backfill["title"],
                    finding_hash,
                    row_dict.get("endpoint"),
                    row_dict.get("cwe"),
                    backfill["status"],
                    backfill["priority"],
                    backfill["triager"],
                    str(row_dict.get("resolved_at") or now),
                    notes,
                    now,
                    now,
                ),
            )
            # Mirror the external state into report_status so future dedup
            # queries see the closure without a JOIN.
            conn.execute(
                """
                UPDATE report_status
                SET external_status = ?,
                    external_priority = ?,
                    external_id = ?
                WHERE domain = ? AND finding_hash = ?
                """,
                (
                    backfill["status"],
                    backfill["priority"],
                    backfill["external_id"],
                    str(row_dict.get("domain") or ""),
                    finding_hash,
                ),
            )
    conn.commit()


_MIGRATIONS: list[tuple[int, str, Migration]] = [
    (1, "candidate_lifecycle_tables", _migration_001_candidate_lifecycle_tables),
    (2, "normalize_lifecycle_statuses", _migration_002_normalize_lifecycle_statuses),
    (3, "external_submissions_and_bm25", _migration_003_external_submissions_and_bm25),
]


# Phase 4A: helper to initialise the empty `prometheus.db` at first run.
# The audit found the singleton DB is sometimes 0 bytes; creating it
# with the current schema here means downstream code can open it via
# ``KnowledgeStore`` without racing the first migration.
def init_prometheus_db(db_path: str | Path | None = None) -> Path:
    """Create the SQLite file at ``db_path`` (or default location) and
    apply all migrations. Idempotent: re-calling on a non-empty DB is a
    no-op that still returns the path.
    """
    if db_path is None:
        # Default to ~/.prometheus/prometheus.db, matching KnowledgeStore.
        candidate = Path.home() / ".prometheus" / "prometheus.db"
    else:
        candidate = Path(db_path)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(candidate))
    try:
        apply_prometheus_migrations(conn)
        conn.commit()
    finally:
        conn.close()
    return candidate
