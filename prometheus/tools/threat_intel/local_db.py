"""Local threat intelligence database — stores all known vulnerabilities for fast offline lookup."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import UTC, datetime
from typing import Any, Self


logger = logging.getLogger(__name__)

DB_PATH = os.path.expanduser("~/.prometheus/prometheus.db")


class ThreatIntelDB:
    """SQLite-backed threat intelligence database.

    Stores CVEs, affected packages, references, exploit data, and EPSS scores.
    Designed for fast local-first querying during scans.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _migrate(self) -> None:
        """Create tables if they don't exist."""
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS cve (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL DEFAULT 0.0,
                epss_score REAL,
                epss_percentile REAL,
                cisa_kev INTEGER DEFAULT 0,
                has_exploit INTEGER DEFAULT 0,
                published_at TEXT,
                updated_at TEXT,
                sources TEXT,
                raw_data TEXT
            );

            CREATE TABLE IF NOT EXISTS cve_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                ecosystem TEXT,
                package_name TEXT NOT NULL,
                vulnerable_version_range TEXT,
                patched_version TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve(cve_id),
                UNIQUE(cve_id, ecosystem, package_name)
            );

            CREATE TABLE IF NOT EXISTS cve_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                url TEXT NOT NULL,
                ref_type TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve(cve_id),
                UNIQUE(cve_id, url)
            );

            CREATE TABLE IF NOT EXISTS feed_status (
                feed_name TEXT PRIMARY KEY,
                last_updated TEXT,
                record_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                error_message TEXT,
                duration_seconds REAL
            );

            CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve(severity);
            CREATE INDEX IF NOT EXISTS idx_cve_epss ON cve(epss_score DESC);
            CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve(cisa_kev);
            CREATE INDEX IF NOT EXISTS idx_cve_exploit ON cve(has_exploit);
            CREATE INDEX IF NOT EXISTS idx_packages_eco_pkg ON cve_packages(ecosystem, package_name);
            CREATE INDEX IF NOT EXISTS idx_packages_cve ON cve_packages(cve_id);
            CREATE INDEX IF NOT EXISTS idx_refs_cve ON cve_references(cve_id);
        """)
        self._conn.commit()

    # -------------------------------------------------------------------------
    # Upsert operations
    # -------------------------------------------------------------------------

    def upsert_cve(
        self,
        cve_id: str,
        description: str = "",
        severity: str = "",
        cvss_score: float = 0.0,
        epss_score: float | None = None,
        epss_percentile: float | None = None,
        cisa_kev: bool = False,
        has_exploit: bool = False,
        published_at: str = "",
        sources: list[str] | None = None,
        raw_data: dict | None = None,
    ) -> None:
        """Insert or update a CVE entry. Merges sources if row exists."""
        now = datetime.now(UTC).isoformat()
        existing = self._conn.execute(
            "SELECT sources FROM cve WHERE cve_id = ?", (cve_id,)
        ).fetchone()

        merged_sources = list(sources or [])
        if existing and existing["sources"]:
            try:
                old_sources = json.loads(existing["sources"])
                for s in old_sources:
                    if s not in merged_sources:
                        merged_sources.append(s)
            except (json.JSONDecodeError, TypeError):
                logger.debug(
                    "existing sources %r not valid JSON, ignoring",
                    existing["sources"],
                    exc_info=True,
                )

        self._conn.execute(
            """
            INSERT INTO cve (cve_id, description, severity, cvss_score,
                epss_score, epss_percentile, cisa_kev, has_exploit,
                published_at, updated_at, sources, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = CASE WHEN excluded.description != '' THEN excluded.description ELSE cve.description END,
                severity = CASE WHEN excluded.severity != '' THEN excluded.severity ELSE cve.severity END,
                cvss_score = CASE WHEN excluded.cvss_score > cve.cvss_score THEN excluded.cvss_score ELSE cve.cvss_score END,
                epss_score = COALESCE(excluded.epss_score, cve.epss_score),
                epss_percentile = COALESCE(excluded.epss_percentile, cve.epss_percentile),
                cisa_kev = CASE WHEN excluded.cisa_kev = 1 THEN 1 ELSE cve.cisa_kev END,
                has_exploit = CASE WHEN excluded.has_exploit = 1 THEN 1 ELSE cve.has_exploit END,
                published_at = CASE WHEN excluded.published_at != '' THEN excluded.published_at ELSE cve.published_at END,
                updated_at = ?,
                sources = ?,
                raw_data = CASE WHEN excluded.raw_data IS NOT NULL THEN excluded.raw_data ELSE cve.raw_data END
        """,
            (
                cve_id,
                description,
                severity,
                cvss_score,
                epss_score,
                epss_percentile,
                1 if cisa_kev else 0,
                1 if has_exploit else 0,
                published_at,
                now,
                json.dumps(merged_sources),
                json.dumps(raw_data) if raw_data else None,
                now,
                json.dumps(merged_sources),
            ),
        )

    def upsert_epss(
        self,
        cve_id: str,
        epss_score: float,
        epss_percentile: float,
    ) -> None:
        """Update EPSS scores for an existing CVE entry. No-op if CVE doesn't exist."""
        self._conn.execute(
            "UPDATE cve SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?",
            (epss_score, epss_percentile, cve_id),
        )

    def upsert_package(
        self,
        cve_id: str,
        ecosystem: str,
        package_name: str,
        vulnerable_version_range: str = "",
        patched_version: str = "",
    ) -> None:
        """Insert or update an affected package entry."""
        self._conn.execute(
            """
            INSERT INTO cve_packages (cve_id, ecosystem, package_name,
                vulnerable_version_range, patched_version)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id, ecosystem, package_name) DO UPDATE SET
                vulnerable_version_range = CASE
                    WHEN excluded.vulnerable_version_range != ''
                    THEN excluded.vulnerable_version_range
                    ELSE cve_packages.vulnerable_version_range END,
                patched_version = CASE
                    WHEN excluded.patched_version != ''
                    THEN excluded.patched_version
                    ELSE cve_packages.patched_version END
        """,
            (cve_id, ecosystem, package_name, vulnerable_version_range, patched_version),
        )

    def upsert_reference(
        self,
        cve_id: str,
        url: str,
        ref_type: str = "",
    ) -> None:
        """Insert a CVE reference (exploit, PoC, advisory, patch)."""
        self._conn.execute(
            """
            INSERT OR IGNORE INTO cve_references (cve_id, url, ref_type)
            VALUES (?, ?, ?)
        """,
            (cve_id, url, ref_type),
        )

    def update_feed_status(
        self,
        feed_name: str,
        status: str,
        record_count: int = 0,
        error_message: str = "",
        duration_seconds: float = 0.0,
    ) -> None:
        """Update feed ingestion status."""
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            """
            INSERT OR REPLACE INTO feed_status (feed_name, last_updated, record_count,
                status, error_message, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (feed_name, now, record_count, status, error_message, duration_seconds),
        )
        self._conn.commit()

    def get_feed_freshness(self, max_age_seconds: int = 86400) -> set[str]:
        """Return set of feed names that were updated within *max_age_seconds*."""
        fresh: set[str] = set()
        try:
            now = datetime.now(UTC)
            for row in self._conn.execute(
                "SELECT feed_name, last_updated FROM feed_status"
            ).fetchall():
                name = row[0]
                updated = row[1]
                if name and updated:
                    try:
                        ts = datetime.fromisoformat(updated).replace(tzinfo=UTC)
                        if (now - ts).total_seconds() < max_age_seconds:
                            fresh.add(name)
                    except (ValueError, TypeError):
                        logger.debug(
                            "updated %r for %s not iso-parseable, skipping",
                            updated,
                            name,
                            exc_info=True,
                        )
        except Exception:
            logger.debug("fresh feed listing failed, returning empty set", exc_info=True)
        return fresh

    def commit(self) -> None:
        """Explicit commit — call after batch operations."""
        self._conn.commit()

    # -------------------------------------------------------------------------
    # Query operations
    # -------------------------------------------------------------------------

    def query_by_package(
        self,
        ecosystem: str,
        package_name: str,
        version: str = "",
        severity_filter: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Query CVEs affecting a specific package, optionally filtered by version."""
        # Normalize package name for LIKE matching
        pkg_pattern = f"%{package_name.lower()}%"

        sql = """
            SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score,
                   c.epss_score, c.epss_percentile, c.cisa_kev, c.has_exploit,
                   c.published_at, c.sources,
                   p.vulnerable_version_range, p.patched_version
            FROM cve c
            JOIN cve_packages p ON c.cve_id = p.cve_id
            WHERE p.ecosystem = ?
              AND (LOWER(p.package_name) LIKE ? OR LOWER(p.package_name) = ?)
        """
        params: list[Any] = [ecosystem.lower(), pkg_pattern, package_name.lower()]

        if severity_filter:
            placeholders = ",".join("?" * len(severity_filter))
            sql += f" AND UPPER(c.severity) IN ({placeholders})"
            params.extend(s.upper() for s in severity_filter)

        sql += " ORDER BY c.cvss_score DESC, c.epss_score DESC NULLS LAST"

        rows = self._conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            result = dict(row)
            # Parse sources JSON
            if result.get("sources"):
                try:
                    result["sources"] = json.loads(result["sources"])
                except (json.JSONDecodeError, TypeError):
                    result["sources"] = []

            # Version range filtering
            if version and result.get("vulnerable_version_range"):
                from prometheus.tools.threat_intel.tool import _version_in_range  # noqa: PLC0415

                if not _version_in_range(version, result["vulnerable_version_range"]):
                    continue  # Skip — version is not in vulnerable range
                result["version_match"] = "vulnerable"
            elif version:
                result["version_match"] = "unknown"

            results.append(result)

        return results

    def query_by_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Get full CVE data including packages and references."""
        row = self._conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
        if not row:
            return None

        result = dict(row)
        if result.get("sources"):
            try:
                result["sources"] = json.loads(result["sources"])
            except (json.JSONDecodeError, TypeError):
                result["sources"] = []

        # Get packages
        pkg_rows = self._conn.execute(
            "SELECT * FROM cve_packages WHERE cve_id = ?", (cve_id,)
        ).fetchall()
        result["packages"] = [dict(r) for r in pkg_rows]

        # Get references
        ref_rows = self._conn.execute(
            "SELECT * FROM cve_references WHERE cve_id = ?", (cve_id,)
        ).fetchall()
        result["references"] = [dict(r) for r in ref_rows]

        return result

    def query_kev_cves(self) -> list[str]:
        """Return all CVE IDs in CISA KEV."""
        rows = self._conn.execute("SELECT cve_id FROM cve WHERE cisa_kev = 1").fetchall()
        return [r["cve_id"] for r in rows]

    def get_epss_scores(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """Return EPSS scores for a list of CVE IDs."""
        if not cve_ids:
            return {}
        placeholders = ",".join("?" * len(cve_ids))
        rows = self._conn.execute(
            f"SELECT cve_id, epss_score, epss_percentile FROM cve WHERE cve_id IN ({placeholders})",
            cve_ids,
        ).fetchall()
        return {
            r["cve_id"]: {
                "epss_score": r["epss_score"],
                "epss_percentile": r["epss_percentile"],
            }
            for r in rows
            if r["epss_score"] is not None
        }

    def get_stats(self) -> dict[str, Any]:
        """Return database statistics."""
        total_cves = self._conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        total_packages = self._conn.execute("SELECT COUNT(*) FROM cve_packages").fetchone()[0]
        total_refs = self._conn.execute("SELECT COUNT(*) FROM cve_references").fetchone()[0]
        kev_count = self._conn.execute("SELECT COUNT(*) FROM cve WHERE cisa_kev = 1").fetchone()[0]
        exploit_count = self._conn.execute(
            "SELECT COUNT(*) FROM cve WHERE has_exploit = 1"
        ).fetchone()[0]
        epss_count = self._conn.execute(
            "SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL"
        ).fetchone()[0]

        # Severity breakdown
        severity_rows = self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM cve WHERE severity != '' GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        severity_breakdown = {r["severity"]: r["cnt"] for r in severity_rows}

        # Feed status
        feed_rows = self._conn.execute("SELECT * FROM feed_status ORDER BY feed_name").fetchall()
        feeds = [dict(r) for r in feed_rows]

        # Ecosystem breakdown
        eco_rows = self._conn.execute(
            "SELECT ecosystem, COUNT(DISTINCT cve_id) as cnt FROM cve_packages WHERE ecosystem != '' GROUP BY ecosystem ORDER BY cnt DESC"
        ).fetchall()
        ecosystem_breakdown = {r["ecosystem"]: r["cnt"] for r in eco_rows}

        return {
            "db_path": self.db_path,
            "total_cves": total_cves,
            "total_packages": total_packages,
            "total_references": total_refs,
            "cisa_kev_count": kev_count,
            "exploit_count": exploit_count,
            "epss_count": epss_count,
            "severity_breakdown": severity_breakdown,
            "ecosystem_breakdown": ecosystem_breakdown,
            "feeds": feeds,
        }

    def count(self) -> int:
        """Quick CVE count."""
        return self._conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
