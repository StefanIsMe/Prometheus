"""CVE auto-trigger watcher for prometheus.

Monitors threat-intel feeds on a cadence and automatically launches
priority scans when newly published CVEs affect technologies discovered
in registered targets.

Singleton — one ``CVEWatcher`` per process.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self


logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / ".prometheus" / "prometheus.db"

_instance: CVEWatcher | None = None
_instance_lock = threading.Lock()


class CVEWatcher:
    """Background daemon that watches for new CVEs affecting registered targets.

    Use ``CVEWatcher()`` — the singleton pattern guarantees one watcher
    per process.

    Lifecycle::

        watcher = CVEWatcher()
        watcher.start()          # launches daemon thread
        watcher.check_now()      # optional manual trigger
        watcher.stop()           # graceful shutdown
    """

    CHECK_INTERVAL = 1800  # 30 minutes in seconds

    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            _instance = inst  # noqa: F841  — singleton assignment read by future __new__ calls
            return inst

    def __init__(self, *, db_path: Path | str | None = None) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._conn: sqlite3.Connection = self._connect()
        self._migrate()
        logger.info("CVEWatcher initialised (db=%s)", self._db_path)

    # ------------------------------------------------------------------
    # SQLite helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS seen_advisories (
                    cve_id      TEXT    NOT NULL,
                    target_id   TEXT    NOT NULL,
                    technology  TEXT    NOT NULL,
                    first_seen  TEXT    NOT NULL,
                    alert_sent  INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (cve_id, target_id, technology)
                );

                CREATE INDEX IF NOT EXISTS idx_seen_alert
                    ON seen_advisories(alert_sent);

                CREATE INDEX IF NOT EXISTS idx_seen_target
                    ON seen_advisories(target_id);

                CREATE TABLE IF NOT EXISTS check_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at  TEXT    NOT NULL,
                    finished_at TEXT,
                    targets_ok  INTEGER DEFAULT 0,
                    targets_err INTEGER DEFAULT 0,
                    new_cves    INTEGER DEFAULT 0,
                    scans_launched INTEGER DEFAULT 0,
                    error       TEXT
                );
                """
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """DISABLED — Prometheus is not a daemon, scans are point-in-time.

        Threat intel is refreshed via ingest_all() at scan start.
        CVEWatcher auto-trigger is not used.
        """
        logger.info("CVEWatcher is disabled — not starting daemon thread")
        return

    def stop(self, timeout: float = 30.0) -> None:
        """Request graceful shutdown and wait for the thread to finish."""
        if self._thread is None or not self._thread.is_alive():
            logger.info("CVEWatcher not running")
            return
        logger.info("CVEWatcher stop requested")
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            logger.warning("CVEWatcher thread did not stop within %.0fs", timeout)
        else:
            logger.info("CVEWatcher stopped")
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Manual trigger
    # ------------------------------------------------------------------

    def check_now(self) -> dict[str, Any]:
        """Execute an immediate check (blocking, runs in the caller's thread).

        Returns a summary dict of what happened.
        """
        logger.info("CVEWatcher manual check triggered")
        return self._run_check()

    # ------------------------------------------------------------------
    # Alert retrieval
    # ------------------------------------------------------------------

    def get_alerts(self, since: str | None = None) -> list[dict[str, Any]]:
        """Return alerts from ``seen_advisories`` where ``alert_sent = 1``.

        Args:
            since: ISO-8601 timestamp.  Only return alerts first seen at or
                   after this time.  ``None`` returns all alerts.
        """
        with self._lock:
            if since:
                rows = self._conn.execute(
                    """
                    SELECT cve_id, target_id, technology, first_seen, alert_sent
                    FROM seen_advisories
                    WHERE alert_sent = 1 AND first_seen >= ?
                    ORDER BY first_seen DESC
                    """,
                    (since,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT cve_id, target_id, technology, first_seen, alert_sent
                    FROM seen_advisories
                    WHERE alert_sent = 1
                    ORDER BY first_seen DESC
                    """,
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Core daemon loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Background loop — runs until ``_stop_event`` is set."""
        # Run immediately on start
        try:
            self._run_check()
        except Exception:
            logger.exception("CVEWatcher initial check failed")

        while not self._stop_event.is_set():
            # Wait for the interval or until stopped
            if self._stop_event.wait(timeout=self.CHECK_INTERVAL):
                break  # stop requested
            try:
                self._run_check()
            except Exception:
                logger.exception("CVEWatcher periodic check failed")
        logger.info("CVEWatcher daemon loop exiting")

    # ------------------------------------------------------------------
    # The actual check logic
    # ------------------------------------------------------------------

    def _run_check(self) -> dict[str, Any]:
        """Single check cycle: refresh feeds, find new CVEs, launch scans."""
        started = datetime.now(UTC).isoformat()
        summary: dict[str, Any] = {
            "started_at": started,
            "new_cves": 0,
            "scans_launched": 0,
            "targets_ok": 0,
            "targets_err": 0,
            "errors": [],
        }

        try:
            # 1. Refresh threat intel feeds
            self._refresh_feeds()

            # 2. Get registered targets
            targets = self._get_active_targets()
            if not targets:
                logger.info("CVEWatcher: no active targets registered")
                return summary

            # 3-4. For each target, check prometheus.db for tech fingerprints
            #      and query local threat intel DB for new CVEs
            from prometheus.tools.threat_intel.local_db import ThreatIntelDB

            with ThreatIntelDB() as intel_db:
                for target in targets:
                    target_id = target.get("id", "")
                    domain = target.get("domain", "")
                    try:
                        new = self._check_target(target, intel_db)
                        summary["new_cves"] += len(new)
                        summary["targets_ok"] += 1

                        # 5-6. Launch scans for new CVEs
                        for alert in new:
                            scan_id = self._launch_scan_for_alert(target, alert)
                            if scan_id:
                                summary["scans_launched"] += 1
                    except Exception:
                        logger.exception(
                            "CVEWatcher: error checking target %s (%s)",
                            target_id,
                            domain,
                        )
                        summary["targets_err"] += 1

        except Exception as exc:
            logger.exception("CVEWatcher: check cycle failed")
            summary["errors"].append(str(exc))

        finished = datetime.now(UTC).isoformat()
        summary["finished_at"] = finished

        # Log the check cycle
        self._log_check(summary)

        logger.info(
            "CVEWatcher check complete: %d new CVEs, %d scans launched, "
            "%d targets ok, %d targets err",
            summary["new_cves"],
            summary["scans_launched"],
            summary["targets_ok"],
            summary["targets_err"],
        )
        return summary

    # ------------------------------------------------------------------
    # Feed refresh
    # ------------------------------------------------------------------

    def _refresh_feeds(self) -> None:
        """Pull latest data from CISA KEV and GHSA into the local DB."""
        from prometheus.tools.threat_intel.local_db import ThreatIntelDB

        with ThreatIntelDB() as intel_db:
            try:
                from prometheus.tools.threat_intel.feeds import (
                    ingest_cisa_kev,
                    ingest_ghsa_bulk,
                )

                logger.info("CVEWatcher: refreshing CISA KEV feed")
                result_kev = ingest_cisa_kev(intel_db)
                logger.info("CVEWatcher: CISA KEV result: %s", result_kev.get("status"))

                logger.info("CVEWatcher: refreshing GHSA feed")
                result_ghsa = ingest_ghsa_bulk(intel_db)
                logger.info("CVEWatcher: GHSA result: %s", result_ghsa.get("status"))
            except Exception:
                logger.exception("CVEWatcher: feed refresh failed")

    # ------------------------------------------------------------------
    # Target lookup
    # ------------------------------------------------------------------

    def _get_active_targets(self) -> list[dict[str, Any]]:
        """Fetch all active targets from the TargetRegistry."""
        from prometheus.core.target_registry import TargetRegistry

        registry = TargetRegistry()
        return registry.list_targets(status="active")

    # ------------------------------------------------------------------
    # Per-target CVE check
    # ------------------------------------------------------------------

    def _check_target(
        self,
        target: dict[str, Any],
        intel_db: Any,  # ThreatIntelDB
    ) -> list[dict[str, Any]]:
        """Check a single target for new CVEs.

        1. Query prometheus.db for ``tech_stack`` entries (technology fingerprints).
        2. For each technology, query the threat intel DB for CVEs.
        3. Compare against seen_advisories — return only NEW ones.

        Returns a list of new alert dicts.
        """
        target_id = target.get("id", "")
        domain = target.get("domain", "")

        fingerprints = self._get_fingerprints(target)
        if not fingerprints:
            logger.debug(
                "CVEWatcher: no fingerprints for target %s (%s)",
                target_id,
                domain,
            )
            return []

        new_alerts: list[dict[str, Any]] = []

        with self._lock:
            for fp in fingerprints:
                tech = fp.get("technology", "").strip()
                version = fp.get("version", "").strip()
                if not tech:
                    continue

                # Determine ecosystem for local DB query
                ecosystem = self._guess_ecosystem(tech)
                pkg_name = tech.lower().strip()

                # Query the threat intel DB
                if ecosystem:
                    cves = intel_db.query_by_package(ecosystem, pkg_name, version)
                else:
                    cves = self._query_cves_by_keyword(intel_db, tech)

                for cve in cves:
                    cve_id = cve.get("cve_id", "")
                    if not cve_id:
                        continue

                    # Check if already seen
                    existing = self._conn.execute(
                        """
                        SELECT 1 FROM seen_advisories
                        WHERE cve_id = ? AND target_id = ? AND technology = ?
                        """,
                        (cve_id, target_id, tech),
                    ).fetchone()

                    if existing is not None:
                        continue  # already seen

                    # New advisory!
                    now = datetime.now(UTC).isoformat()
                    self._conn.execute(
                        """
                        INSERT OR IGNORE INTO seen_advisories
                            (cve_id, target_id, technology, first_seen, alert_sent)
                        VALUES (?, ?, ?, ?, 0)
                        """,
                        (cve_id, target_id, tech, now),
                    )
                    new_alerts.append(
                        {
                            "cve_id": cve_id,
                            "technology": tech,
                            "version": version,
                            "severity": cve.get("severity", ""),
                            "cvss_score": cve.get("cvss_score", 0.0),
                            "description": cve.get("description", "")[:200],
                            "cisa_kev": bool(cve.get("cisa_kev")),
                            "has_exploit": bool(cve.get("has_exploit")),
                        }
                    )

            self._conn.commit()

        if new_alerts:
            logger.info(
                "CVEWatcher: %d new CVEs for target %s (%s)",
                len(new_alerts),
                target_id,
                domain,
            )
        return new_alerts

    # ------------------------------------------------------------------
    # Knowledge lookup for technology fingerprints
    # ------------------------------------------------------------------

    def _get_fingerprints(self, target: dict[str, Any]) -> list[dict[str, str]]:
        """Retrieve technology fingerprints for a target.

        Sources (in order):
        1. ``target_config.tech_stack`` stored in the target registry.
        2. ``prometheus.db`` ``tech_stack`` category entries for the domain.
        """
        fingerprints: list[dict[str, str]] = []
        seen: set[str] = set()

        # From target_config
        target_config = target.get("target_config") or {}
        tech_stack = target_config.get("tech_stack") or []
        for entry in tech_stack:
            tech = (entry.get("technology") or "").strip()
            version = (entry.get("version") or "").strip()
            key = f"{tech}@{version}".lower()
            if tech and key not in seen:
                seen.add(key)
                fingerprints.append({"technology": tech, "version": version})

        # From prometheus.db
        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            ks = KnowledgeStore()
            domain = target.get("domain", "")
            entries = ks.query(domain, category="tech_stack")
            for entry in entries:
                key_raw = entry.get("key", "")
                value_raw = entry.get("value", "")
                # key is typically the technology name, value is version/details
                tech = key_raw.strip()
                version = value_raw.strip()
                cache_key = f"{tech}@{version}".lower()
                if tech and cache_key not in seen:
                    seen.add(cache_key)
                    fingerprints.append({"technology": tech, "version": version})
        except Exception:
            logger.debug(
                "CVEWatcher: could not load knowledge for %s",
                target.get("domain", ""),
                exc_info=True,
            )

        return fingerprints

    # ------------------------------------------------------------------
    # Ecosystem helpers (duplicated from query_engine to avoid circular imports)
    # ------------------------------------------------------------------

    _ECOSYSTEM_MAP: dict[str, str] = {
        "npm": "npm",
        "node": "npm",
        "next.js": "npm",
        "nextjs": "npm",
        "react": "npm",
        "express": "npm",
        "angular": "npm",
        "vue": "npm",
        "nuxt": "npm",
        "python": "pypi",
        "pip": "pypi",
        "flask": "pypi",
        "django": "pypi",
        "fastapi": "pypi",
        "uvicorn": "pypi",
        "go": "go",
        "golang": "go",
        "rust": "crates.io",
        "cargo": "crates.io",
        "ruby": "rubygems",
        "rails": "rubygems",
        "gem": "rubygems",
        "java": "maven",
        "maven": "maven",
        "spring": "maven",
        "php": "packagist",
        "composer": "packagist",
        "laravel": "packagist",
        "nuget": "nuget",
        ".net": "nuget",
        "csharp": "nuget",
        "swift": "swift",
    }

    @classmethod
    def _guess_ecosystem(cls, tech: str) -> str | None:
        tech_lower = tech.lower().strip()
        if tech_lower in cls._ECOSYSTEM_MAP:
            return cls._ECOSYSTEM_MAP[tech_lower]
        for key, eco in cls._ECOSYSTEM_MAP.items():
            if key in tech_lower:
                return eco
        return None

    @staticmethod
    def _query_cves_by_keyword(
        intel_db: Any,
        tech: str,
    ) -> list[dict[str, Any]]:
        """Fall back to LIKE search on CVE description when no ecosystem match."""
        pattern = f"%{tech.lower()}%"
        try:
            rows = intel_db._conn.execute(
                """
                SELECT cve_id, description, severity, cvss_score,
                       cisa_kev, has_exploit, published_at
                FROM cve
                WHERE LOWER(description) LIKE ?
                  AND severity IN ('CRITICAL', 'HIGH')
                ORDER BY cvss_score DESC
                LIMIT 50
                """,
                (pattern,),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            logger.debug("CVEWatcher: keyword query failed for '%s'", tech, exc_info=True)
            return []

    # ------------------------------------------------------------------
    # Scan launching
    # ------------------------------------------------------------------

    def _launch_scan_for_alert(
        self,
        target: dict[str, Any],
        alert: dict[str, Any],
    ) -> str | None:
        """Launch a priority scan for a newly discovered CVE.

        Marks the advisory as ``alert_sent = 1`` on success.
        """
        target_id = target.get("id", "")
        cve_id = alert.get("cve_id", "")
        tech = alert.get("technology", "unknown")
        severity = alert.get("severity", "UNKNOWN")
        cvss = alert.get("cvss_score", 0.0)

        instruction = (
            f"New CVE {cve_id} affects {tech} (severity={severity}, "
            f"CVSS={cvss}). Test for this vulnerability. "
            f"Description: {alert.get('description', 'N/A')}"
        )

        try:
            from prometheus.core.orchestrator import ScanOrchestrator

            orchestrator = ScanOrchestrator()

            scan_config = {
                "instructions": instruction,
            }

            scan_id = orchestrator.launch_scan(
                target_id=target_id,
                scan_config=scan_config,
            )

            # Mark advisory as sent
            with self._lock:
                self._conn.execute(
                    """
                    UPDATE seen_advisories
                    SET alert_sent = 1
                    WHERE cve_id = ? AND target_id = ? AND technology = ?
                    """,
                    (cve_id, target_id, tech),
                )
                self._conn.commit()

            logger.info(
                "CVEWatcher: launched scan %s for %s on target %s (%s)",
                scan_id,
                cve_id,
                target_id,
                target.get("domain", ""),
            )
            return scan_id

        except Exception:
            logger.exception(
                "CVEWatcher: failed to launch scan for %s on target %s",
                cve_id,
                target_id,
            )
            return None

    # ------------------------------------------------------------------
    # Check log
    # ------------------------------------------------------------------

    def _log_check(self, summary: dict[str, Any]) -> None:
        """Persist the check cycle summary."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO check_log
                    (started_at, finished_at, targets_ok, targets_err,
                     new_cves, scans_launched, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.get("started_at", ""),
                    summary.get("finished_at", ""),
                    summary.get("targets_ok", 0),
                    summary.get("targets_err", 0),
                    summary.get("new_cves", 0),
                    summary.get("scans_launched", 0),
                    "; ".join(summary.get("errors", [])) or None,
                ),
            )
            self._conn.commit()
