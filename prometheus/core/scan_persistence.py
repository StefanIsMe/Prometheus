"""Persistent scan state backed by SQLite.

Stores scan lifecycle so scans survive TUI restarts and can be resumed.
Thread-safe singleton pattern — one ``ScanPersistence`` instance per process.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

_instance: ScanPersistence | None = (
    None  # codeql[py/unused-global-variable] : read via `global` inside ScanPersistence.__new__
)
_instance_lock = threading.Lock()


class ScanPersistence:
    """SQLite-backed persistent store for scan state.

    Use ``ScanPersistence()`` — the singleton pattern guarantees one
    connection per process.
    """

    def __new__(cls, db_path: Path | str | None = None) -> "ScanPersistence":
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            inst._init(db_path)  # type: ignore[attr-defined]
            _instance = inst  # noqa: F841  — singleton assignment read by future __new__ calls  # codeql[py/unused-global-variable] : suppressed via the security dashboard triage
            return inst

    # ------------------------------------------------------------------
    # Internal init (called once)
    # ------------------------------------------------------------------

    def _init(self, db_path: Path | str | None = None) -> None:
        from prometheus.tools.knowledge.store import KnowledgeStore

        self._store = KnowledgeStore(db_path)
        self._lock = self._store._lock
        self._db_path = self._store._db_path
        self._conn = self._store._conn
        self._create_tables()
        logger.info("ScanPersistence compatibility wrapper initialised at %s", self._db_path)

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id        TEXT PRIMARY KEY,
                    target_id      TEXT,
                    target_name    TEXT,
                    run_name       TEXT,
                    status         TEXT NOT NULL DEFAULT 'running',
                    started_at     TEXT,
                    ended_at       TEXT,
                    findings_count INTEGER DEFAULT 0,
                    run_dir        TEXT,
                    scan_config    TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_scans_status
                    ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_scans_target_id
                    ON scans(target_id);
                """
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_scan_start(
        self,
        scan_id: str,
        target_id: str,
        target_name: str,
        run_name: str,
        scan_config: dict[str, Any],
        run_dir: str = "",
    ) -> None:
        """Record that a scan has started."""
        now = datetime.now(UTC).isoformat()
        config_json = json.dumps(scan_config, ensure_ascii=False)

        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO scans
                    (scan_id, target_id, target_name, run_name,
                     status, started_at, findings_count, run_dir, scan_config)
                VALUES (?, ?, ?, ?, 'running', ?, 0, ?, ?)
                """,
                (scan_id, target_id, target_name, run_name, now, run_dir, config_json),
            )
            self._conn.commit()

        logger.info(
            "Recorded scan start: id=%s target=%s run=%s",
            scan_id,
            target_name,
            run_name,
        )

    def record_scan_end(
        self,
        scan_id: str,
        status: str = "completed",
        findings_count: int = 0,
    ) -> None:
        """Record that a scan has ended."""
        now = datetime.now(UTC).isoformat()

        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE scans
                SET status = ?, ended_at = ?, findings_count = ?
                WHERE scan_id = ?
                """,
                (status, now, findings_count, scan_id),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                logger.warning(
                    "record_scan_end: scan_id=%s not found",
                    scan_id,
                )
                return

        logger.info(
            "Recorded scan end: id=%s status=%s findings=%d",
            scan_id,
            status,
            findings_count,
        )

    def get_incomplete_scans(self) -> list[dict[str, Any]]:
        """Get scans with status 'running' or 'paused'."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM scans
                WHERE status IN ('running', 'paused')
                ORDER BY started_at DESC
                """,
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_all_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get all scans, most recent first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Get a single scan by id, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record. Returns True if a row was deleted."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM scans WHERE scan_id = ?",
                (scan_id,),
            )
            self._conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            logger.info("Deleted scan record: %s", scan_id)
        return deleted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if "scan_config" in d and isinstance(d["scan_config"], str):
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                d["scan_config"] = json.loads(d["scan_config"])
        return d
