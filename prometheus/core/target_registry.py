"""Persistent target registry backed by SQLite.

Stores scan targets so they can be managed, scheduled, and tracked
across runs.  Thread-safe singleton pattern — one ``TargetRegistry``
instance per process.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self


logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".prometheus" / "prometheus.db"

_instance: TargetRegistry | None = None
_instance_lock = threading.Lock()


class TargetRegistry:
    """SQLite-backed persistent store for scan targets.

    Use ``TargetRegistry()`` — the singleton pattern guarantees one
    connection per process.
    """

    def __new__(cls, db_path: Path | str | None = None) -> Self:
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            inst._init(db_path)  # type: ignore[attr-defined]
            _instance = inst
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
        logger.info("TargetRegistry compatibility wrapper initialised at %s", self._db_path)

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id            TEXT PRIMARY KEY,
                    domain        TEXT    NOT NULL,
                    target_type   TEXT    NOT NULL,
                    target_config TEXT    NOT NULL DEFAULT '{}',
                    scan_config   TEXT    NOT NULL DEFAULT '{}',
                    schedule      TEXT    NOT NULL DEFAULT '{}',
                    status        TEXT    NOT NULL DEFAULT 'active',
                    created_at    TEXT    NOT NULL,
                    updated_at    TEXT    NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_targets_domain
                    ON targets(domain);
                CREATE INDEX IF NOT EXISTS idx_targets_status
                    ON targets(status);
                CREATE INDEX IF NOT EXISTS idx_targets_type
                    ON targets(target_type);
                """
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_target(
        self,
        domain: str,
        target_type: str,
        target_config: dict[str, Any] | None = None,
        scan_config: dict[str, Any] | None = None,
        schedule: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Add a new target.  Returns the created target record."""
        target_id = uuid.uuid4().hex[:12]
        now = datetime.now(UTC).isoformat()
        target_config_json = json.dumps(target_config or {}, ensure_ascii=False)
        scan_config_json = json.dumps(scan_config or {}, ensure_ascii=False)
        schedule_json = json.dumps(schedule or {}, ensure_ascii=False)

        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM targets WHERE domain = ? ORDER BY created_at DESC LIMIT 1",
                (domain,),
            ).fetchone()
            if existing is not None:
                target_id = existing["id"]
                self._conn.execute(
                    """
                    UPDATE targets
                    SET target_type = ?, target_config = ?, scan_config = ?,
                        schedule = ?, status = 'active', updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        target_type,
                        target_config_json,
                        scan_config_json,
                        schedule_json,
                        now,
                        target_id,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO targets
                        (id, domain, target_type, target_config, scan_config,
                         schedule, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (
                        target_id,
                        domain,
                        target_type,
                        target_config_json,
                        scan_config_json,
                        schedule_json,
                        now,
                        now,
                    ),
                )
            self._conn.commit()

        logger.info("Added target id=%s domain=%s type=%s", target_id, domain, target_type)
        return {
            "success": True,
            "id": target_id,
            "domain": domain,
            "target_type": target_type,
            "status": "active",
            "created_at": now,
        }

    def remove_target(self, target_id: str) -> dict[str, Any]:
        """Remove a target by id.  Returns success/error."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            self._conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "error": f"Target '{target_id}' not found"}

        logger.info("Removed target id=%s", target_id)
        return {"success": True, "id": target_id}

    def list_targets(self, status: str = "active") -> list[dict[str, Any]]:
        """List targets filtered by status."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM targets WHERE status = ? ORDER BY created_at DESC",
                (status,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        """Get a single target by id, or None."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def update_target(
        self,
        target_id: str,
        *,
        instructions: str | None = None,
        interval_hours: int | None = None,
        status: str | None = None,
        target_config: dict[str, Any] | None = None,
        scan_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update mutable fields on a target.  Only non-None args are changed."""
        now = datetime.now(UTC).isoformat()
        sets: list[str] = ["updated_at = ?"]
        params: list[Any] = [now]

        # Merge scan_config changes
        if instructions is not None or scan_config is not None:
            with self._lock:
                row = self._conn.execute(
                    "SELECT scan_config FROM targets WHERE id = ?", (target_id,)
                ).fetchone()
                if row is None:
                    return {"success": False, "error": f"Target '{target_id}' not found"}
                existing = json.loads(row["scan_config"])
            if instructions is not None:
                existing["instructions"] = instructions
            if scan_config is not None:
                existing.update(scan_config)
            sets.append("scan_config = ?")
            params.append(json.dumps(existing, ensure_ascii=False))

        # Merge schedule changes
        if interval_hours is not None:
            with self._lock:
                row = self._conn.execute(
                    "SELECT schedule FROM targets WHERE id = ?", (target_id,)
                ).fetchone()
                if row is None:
                    return {"success": False, "error": f"Target '{target_id}' not found"}
                existing_sched = json.loads(row["schedule"])
            existing_sched["interval_hours"] = interval_hours
            sets.append("schedule = ?")
            params.append(json.dumps(existing_sched, ensure_ascii=False))

        if status is not None:
            sets.append("status = ?")
            params.append(status)

        if target_config is not None:
            with self._lock:
                row = self._conn.execute(
                    "SELECT target_config FROM targets WHERE id = ?", (target_id,)
                ).fetchone()
                if row is None:
                    return {"success": False, "error": f"Target '{target_id}' not found"}
                existing_tc = json.loads(row["target_config"])
            existing_tc.update(target_config)
            sets.append("target_config = ?")
            params.append(json.dumps(existing_tc, ensure_ascii=False))

        params.append(target_id)
        sql = f"UPDATE targets SET {', '.join(sets)} WHERE id = ?"

        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            if cur.rowcount == 0:
                return {"success": False, "error": f"Target '{target_id}' not found"}

        logger.info("Updated target id=%s", target_id)
        return {"success": True, "id": target_id}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        # Parse JSON fields
        for field in ("target_config", "scan_config", "schedule"):
            if field in d and isinstance(d[field], str):
                with contextlib.suppress(json.JSONDecodeError, TypeError):
                    d[field] = json.loads(d[field])
        return d
