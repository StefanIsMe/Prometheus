"""Canonical candidate persistence backed by KnowledgeStore."""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from prometheus.core.candidate_normalizer import normalize_finding
from prometheus.core.candidate_schema import (
    EVIDENCE_KINDS,
    VALIDATORS,
    EvidenceArtifact,
    FindingCandidate,
    assert_legal_transition,
)
from prometheus.core.comms import get_active_run, write_status
from prometheus.tools.knowledge.store import KnowledgeStore


class CandidateStore:
    """Canonical persistence API for finding candidates and evidence."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._knowledge_store = KnowledgeStore(db_path)
        self._conn = self._knowledge_store._conn
        self._lock = self._knowledge_store._lock

    def upsert_candidate(self, candidate: FindingCandidate) -> dict[str, Any]:
        feedback_hint = self._feedback_rejection_hint(candidate)
        if feedback_hint and candidate.lifecycle_status in {"new", "needs_review"}:
            candidate.lifecycle_status = "rejected"  # type: ignore[assignment]
            candidate.rejection_reason = feedback_hint
        row = candidate.to_row()
        with self._lock:
            existing = self._conn.execute(
                "SELECT id, lifecycle_status FROM finding_candidates WHERE domain = ? AND fingerprint = ?",
                (candidate.domain, candidate.fingerprint),
            ).fetchone()
            self._conn.execute(
                """
                INSERT INTO finding_candidates (
                    id, domain, scan_id, source_tool, source_type, title, vuln_type,
                    severity, confidence, endpoint, method, parameter, auth_state,
                    role, workflow_step, fingerprint, lifecycle_status,
                    rejection_reason, raw_finding_json, created_at, updated_at, last_seen_at
                ) VALUES (
                    :id, :domain, :scan_id, :source_tool, :source_type, :title, :vuln_type,
                    :severity, :confidence, :endpoint, :method, :parameter, :auth_state,
                    :role, :workflow_step, :fingerprint, :lifecycle_status,
                    :rejection_reason, :raw_finding_json, :created_at, :updated_at, :last_seen_at
                )
                ON CONFLICT(domain, fingerprint) DO UPDATE SET
                    scan_id = excluded.scan_id,
                    source_tool = excluded.source_tool,
                    source_type = excluded.source_type,
                    title = excluded.title,
                    vuln_type = excluded.vuln_type,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    endpoint = excluded.endpoint,
                    method = excluded.method,
                    parameter = excluded.parameter,
                    auth_state = excluded.auth_state,
                    role = excluded.role,
                    workflow_step = excluded.workflow_step,
                    rejection_reason = COALESCE(excluded.rejection_reason, finding_candidates.rejection_reason),
                    raw_finding_json = excluded.raw_finding_json,
                    updated_at = excluded.updated_at,
                    last_seen_at = excluded.last_seen_at,
                    lifecycle_status = CASE
                        WHEN finding_candidates.lifecycle_status IN ('new', 'needs_review')
                             AND excluded.lifecycle_status = 'rejected'
                        THEN 'rejected'
                        ELSE finding_candidates.lifecycle_status
                    END
                """,
                row,
            )
            self._conn.commit()
            stored = self.get_by_domain_fingerprint(candidate.domain, candidate.fingerprint)
        # Live observability: tell the tailer a finding landed. Best-effort.
        try:
            _rid = get_active_run()
            if _rid and stored is not None:
                write_status(
                    _rid,
                    "finding_validated",
                    {
                        "id": stored.get("id", candidate.id),
                        "domain": stored.get("domain", ""),
                        "severity": stored.get("severity", "?"),
                        "title": stored.get("title", "") or "",
                        "endpoint": stored.get("endpoint", ""),
                        "lifecycle": stored.get("lifecycle_status", ""),
                    },
                )
        except Exception:
            logger.debug("finding_validated write_status failed", exc_info=True)
        return {
            "success": True,
            "action": "updated" if existing else "created",
            "id": stored["id"] if stored else candidate.id,
            "candidate": stored,
        }

    def ingest_raw_finding(
        self,
        raw: dict[str, Any],
        *,
        domain: str,
        scan_id: str,
        source_tool: str = "agent",
        source_type: str = "agent_finding",
    ) -> dict[str, Any]:
        candidate = normalize_finding(
            raw,
            domain=domain,
            scan_id=scan_id,
            source_tool=source_tool,
            source_type=source_type,
        )
        try:
            return self.upsert_candidate(candidate)
        except sqlite3.IntegrityError:
            # Race condition: another thread/process inserted between our
            # SELECT check and INSERT.  Fall back to a pure UPDATE.
            logger.debug(
                "IntegrityError during upsert — retrying as update for %s/%s",
                candidate.domain,
                candidate.fingerprint,
            )
            with self._lock:
                existing = self._conn.execute(
                    "SELECT id, lifecycle_status FROM finding_candidates WHERE domain = ? AND fingerprint = ?",
                    (candidate.domain, candidate.fingerprint),
                ).fetchone()
                if existing:
                    row = candidate.to_row()
                    self._conn.execute(
                        """UPDATE finding_candidates SET
                            scan_id = :scan_id, source_tool = :source_tool,
                            source_type = :source_type, title = :title,
                            vuln_type = :vuln_type, severity = :severity,
                            confidence = :confidence, endpoint = :endpoint,
                            method = :method, parameter = :parameter,
                            auth_state = :auth_state, role = :role,
                            workflow_step = :workflow_step,
                            raw_finding_json = :raw_finding_json,
                            updated_at = :updated_at,
                            last_seen_at = :last_seen_at
                        WHERE id = ?""",
                        {**row, "id": existing["id"]},
                    )
                    self._conn.commit()
                stored = self.get_by_domain_fingerprint(candidate.domain, candidate.fingerprint)
            return {
                "success": True,
                "action": "updated",
                "id": stored["id"] if stored else candidate.id,
                "candidate": stored,
            }

    def ingest_findings(
        self,
        findings: list[dict[str, Any]],
        *,
        domain: str,
        scan_id: str,
        source_tool: str = "agent",
        source_type: str = "agent_finding",
    ) -> dict[str, Any]:
        created = 0
        updated = 0
        rejected = 0
        ids: list[str] = []
        for finding in findings:
            result = self.ingest_raw_finding(
                finding,
                domain=domain,
                scan_id=scan_id,
                source_tool=source_tool,
                source_type=source_type,
            )
            ids.append(str(result.get("id")))
            if result.get("action") == "created":
                created += 1
            else:
                updated += 1
            candidate = result.get("candidate") or {}
            if candidate.get("lifecycle_status") == "rejected":
                rejected += 1
        return {
            "success": True,
            "created": created,
            "updated": updated,
            "rejected": rejected,
            "ids": ids,
        }

    def get_candidate(self, finding_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM finding_candidates WHERE id = ?", (finding_id,)
            ).fetchone()
        return _row_to_dict(row) if row else None

    def get_by_domain_fingerprint(self, domain: str, fingerprint: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM finding_candidates WHERE domain = ? AND fingerprint = ?",
                (domain, fingerprint),
            ).fetchone()
        return _row_to_dict(row) if row else None

    def get_candidate_for_report(self, report: dict[str, Any]) -> dict[str, Any] | None:
        domain = str(report.get("domain") or "")
        fingerprint = str(report.get("finding_hash") or "")
        if domain and fingerprint:
            found = self.get_by_domain_fingerprint(domain, fingerprint)
            if found:
                return found
        report_id = report.get("id")
        if report_id is not None:
            return self.get_candidate(f"report-{report_id}")
        return None

    def list_candidates(
        self, *, status: str | None = None, domain: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("lifecycle_status = ?")
            params.append(status)
        if domain:
            clauses.append("domain = ?")
            params.append(domain)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM finding_candidates {where} ORDER BY updated_at DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def add_evidence(
        self,
        *,
        finding_id: str,
        evidence_kind: str,
        summary: str | None = None,
        path: str | None = None,
        inline: dict[str, Any] | list[Any] | str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if evidence_kind not in EVIDENCE_KINDS:
            raise ValueError(f"Unsupported evidence kind: {evidence_kind}")
        inline_json = _json_dumps(inline) if inline is not None else None
        metadata_json = _json_dumps(metadata) if metadata is not None else None
        artifact = EvidenceArtifact(
            id=f"ev-{uuid.uuid4().hex[:12]}",
            finding_id=finding_id,
            evidence_kind=evidence_kind,
            summary=summary,
            path=path,
            inline_json=inline_json,
            metadata_json=metadata_json,
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO finding_evidence
                    (id, finding_id, evidence_kind, summary, path, inline_json, metadata_json, created_at)
                VALUES (:id, :finding_id, :evidence_kind, :summary, :path, :inline_json, :metadata_json, :created_at)
                """,
                artifact.to_row(),
            )
            self._conn.commit()
        return {"success": True, "id": artifact.id}

    def list_evidence(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM finding_evidence WHERE finding_id = ? ORDER BY created_at ASC",
                (finding_id,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def record_validation_run(
        self,
        *,
        finding_id: str,
        validator: str,
        status: str,
        output: dict[str, Any] | list[Any] | str,
        confidence: float | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        if validator not in VALIDATORS:
            raise ValueError(f"Unsupported validator: {validator}")
        now = datetime.now(UTC).isoformat()
        run_id = f"vr-{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO validation_runs
                    (id, finding_id, validator, status, confidence, output_json, started_at, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding_id,
                    validator,
                    status,
                    confidence,
                    _json_dumps(output),
                    started_at or now,
                    finished_at or now,
                ),
            )
            self._conn.commit()
        return {"success": True, "id": run_id}

    def list_validation_runs(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM validation_runs WHERE finding_id = ? ORDER BY started_at ASC",
                (finding_id,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def can_mark_ready_to_submit(self, finding_id: str) -> bool:
        evidence_count = len(self.list_evidence(finding_id))
        if evidence_count == 0:
            return False
        runs = self.list_validation_runs(finding_id)
        good_statuses = {"success", "passed", "verified", "completed"}
        return any(str(run.get("status") or "").lower() in good_statuses for run in runs)

    def transition_status(
        self,
        finding_id: str,
        to_status: str,
        *,
        actor: str = "system",
        reason: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        candidate = self.get_candidate(finding_id)
        if not candidate:
            return {"success": False, "error": f"Finding candidate not found: {finding_id}"}
        from_status = str(candidate.get("lifecycle_status") or "new")
        assert_legal_transition(from_status, to_status)
        if to_status == "ready_to_submit" and not self.can_mark_ready_to_submit(finding_id):
            raise ValueError(
                "ready_to_submit requires stored evidence and a successful validation run"
            )
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE finding_candidates SET lifecycle_status = ?, rejection_reason = COALESCE(?, rejection_reason), updated_at = ? WHERE id = ?",
                (to_status, reason, now, finding_id),
            )
            self._update_report_projection_locked(candidate, to_status, now)
            self._log_event_locked(
                finding_id=finding_id,
                event_type="status_transition",
                from_status=from_status,
                to_status=to_status,
                actor=actor,
                payload={"reason": reason, **(payload or {})},
            )
            self._conn.commit()
        return {
            "success": True,
            "id": finding_id,
            "from_status": from_status,
            "to_status": to_status,
        }

    def add_submission_artifact(
        self,
        *,
        finding_id: str,
        platform: str,
        artifact_type: str,
        path: str,
        sha256: str,
    ) -> dict[str, Any]:
        version = self.next_artifact_version(finding_id, platform, artifact_type)
        artifact_id = f"art-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO submission_artifacts
                    (id, finding_id, platform, artifact_type, version, path, sha256, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (artifact_id, finding_id, platform, artifact_type, version, path, sha256, now),
            )
            self._conn.commit()
        return {"success": True, "id": artifact_id, "version": version}

    def next_artifact_version(self, finding_id: str, platform: str, artifact_type: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS max_version FROM submission_artifacts WHERE finding_id = ? AND platform = ? AND artifact_type = ?",
                (finding_id, platform, artifact_type),
            ).fetchone()
        return int(row["max_version"] or 0) + 1

    def list_artifacts(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM submission_artifacts WHERE finding_id = ? ORDER BY created_at DESC",
                (finding_id,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def record_submission_outcome(
        self,
        *,
        finding_id: str,
        outcome: str,
        comments: str = "",
        actor: str = "human",
        platform: str | None = None,
        report_url: str | None = None,
    ) -> dict[str, Any]:
        status = {"informative": "rejected", "na": "rejected"}.get(outcome, outcome)
        if status not in {"accepted", "duplicate", "rejected"}:
            raise ValueError(f"Unsupported outcome: {outcome}")
        candidate = self.get_candidate(finding_id)
        if not candidate:
            return {"success": False, "error": f"Finding candidate not found: {finding_id}"}
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE finding_candidates SET lifecycle_status = ?, updated_at = ? WHERE id = ?",
                (status, now, finding_id),
            )
            self._update_report_projection_locked(
                candidate, status, now, platform=platform, report_url=report_url
            )
            self._log_event_locked(
                finding_id=finding_id,
                event_type="submission_outcome",
                from_status=str(candidate.get("lifecycle_status") or ""),
                to_status=status,
                actor=actor,
                payload={
                    "outcome": outcome,
                    "comments": comments,
                    "platform": platform,
                    "report_url": report_url,
                },
            )
            self._update_feedback_rule_locked(candidate, outcome, comments, now)
            self._conn.commit()
        return {"success": True, "id": finding_id, "outcome": outcome, "status": status}

    def outcome_summary(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT lifecycle_status, COUNT(*) AS count FROM finding_candidates GROUP BY lifecycle_status"
            ).fetchall()
            rules = self._conn.execute(
                "SELECT * FROM outcome_feedback_rules ORDER BY updated_at DESC LIMIT 100"
            ).fetchall()
        return {
            "by_status": {row["lifecycle_status"]: row["count"] for row in rows},
            "feedback_rules": [_row_to_dict(row) for row in rules],
        }

    def _update_report_projection_locked(
        self,
        candidate: dict[str, Any],
        status: str,
        now: str,
        *,
        platform: str | None = None,
        report_url: str | None = None,
    ) -> None:
        report_status = _candidate_status_to_report_status(status)
        sets = ["status = ?", "updated_at = ?"]
        params: list[Any] = [report_status, now]
        if platform is not None:
            sets.append("platform = ?")
            params.append(platform)
        if report_url is not None:
            sets.append("report_url = ?")
            params.append(report_url)
        if report_status == "submitted":
            sets.append("submitted_at = COALESCE(submitted_at, ?)")
            params.append(now)
        if report_status in {"accepted", "rejected", "duplicate"}:
            sets.append("resolved_at = COALESCE(resolved_at, ?)")
            params.append(now)
        params.extend([candidate.get("domain"), candidate.get("fingerprint")])
        self._conn.execute(
            f"UPDATE report_status SET {', '.join(sets)} WHERE domain = ? AND finding_hash = ?",
            params,
        )

    def _log_event_locked(
        self,
        *,
        finding_id: str,
        event_type: str,
        from_status: str | None,
        to_status: str | None,
        actor: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO submission_events
                (finding_id, event_type, from_status, to_status, actor, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                event_type,
                from_status,
                to_status,
                actor,
                _json_dumps(payload or {}),
                datetime.now(UTC).isoformat(),
            ),
        )

    def _feedback_rejection_hint(self, candidate: FindingCandidate) -> str | None:
        rule_key = f"{candidate.vuln_type}|{candidate.endpoint or ''}".lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT rejected_count, duplicate_count, accepted_count, rejection_hint FROM outcome_feedback_rules WHERE rule_key = ?",
                (rule_key,),
            ).fetchone()
        if not row:
            return None
        rejected = int(row["rejected_count"] or 0)
        duplicates = int(row["duplicate_count"] or 0)
        accepted = int(row["accepted_count"] or 0)
        if rejected + duplicates > accepted:
            return str(row["rejection_hint"] or "similar prior outcome was rejected or duplicate")
        return None

    def _update_feedback_rule_locked(
        self, candidate: dict[str, Any], outcome: str, comments: str, now: str
    ) -> None:
        vuln_type = str(candidate.get("vuln_type") or "unknown")
        # Don't cap endpoint for the rule_key; SQLite TEXT is unlimited
        # and a 200-char cap here was dropping the path/query that makes
        # the rule distinguishable (e.g. "/api/v1/users/123" gets cut to
        # "/api/v1/users/..." the moment a longer URL is in play).
        endpoint = str(candidate.get("endpoint") or "")
        rule_key = f"{vuln_type}|{endpoint}".lower()
        rejected_inc = 1 if outcome in {"rejected", "informative", "na"} else 0
        duplicate_inc = 1 if outcome == "duplicate" else 0
        accepted_inc = 1 if outcome == "accepted" else 0
        rejection_hint = comments[:500] if rejected_inc or duplicate_inc else None
        self._conn.execute(
            """
            INSERT INTO outcome_feedback_rules
                (rule_key, vuln_type, endpoint_pattern, outcome, rejection_hint,
                 accepted_count, rejected_count, duplicate_count,
                 last_seen_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_key) DO UPDATE SET
                outcome = excluded.outcome,
                rejection_hint = COALESCE(excluded.rejection_hint, outcome_feedback_rules.rejection_hint),
                accepted_count = accepted_count + excluded.accepted_count,
                rejected_count = rejected_count + excluded.rejected_count,
                duplicate_count = duplicate_count + excluded.duplicate_count,
                last_seen_at = excluded.last_seen_at,
                updated_at = excluded.updated_at
            """,
            (
                rule_key,
                vuln_type,
                endpoint,
                outcome,
                rejection_hint,
                accepted_inc,
                rejected_inc,
                duplicate_inc,
                now,
                now,
                now,
            ),
        )


def _candidate_status_to_report_status(status: str) -> str:
    return {
        "needs_review": "new",
        "validating": "reviewing",
        "verified": "reviewing",
        "ready_to_submit": "new",
        "archived": "dismissed",
    }.get(status, status)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def _json_dumps(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)
