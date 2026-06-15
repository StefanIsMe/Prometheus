"""Hypothesis portfolio for novel vulnerability discovery.

The scanner finds novel issues by turning target behaviour into structured
hypotheses, collecting positive and negative controls, then only allowing
reports when a hypothesis has a concrete validation trail.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from prometheus.tools.knowledge.store import KnowledgeStore


VALID_HYPOTHESIS_STATUSES: set[str] = {
    "new",
    "selected",
    "testing",
    "needs_validation",
    "validated",
    "dead_end",
    "abandoned",
    "reported",
}

ACTIVE_HYPOTHESIS_STATUSES: set[str] = {
    "new",
    "selected",
    "testing",
    "needs_validation",
}


@dataclass(slots=True)
class DifficultyFactors:
    """Inputs for task difficulty scoring.

    Values are normalized to 0.0-1.0 before scoring.
    """

    horizon: float = 0.0
    unknowns: float = 0.0
    context_load: float = 0.0
    state_complexity: float = 0.0
    tool_risk: float = 0.0


@dataclass(slots=True)
class HypothesisEvidence:
    """Evidence linked to one hypothesis."""

    id: str
    evidence_type: str
    summary: str
    request: dict[str, Any] = field(default_factory=dict)
    response_fingerprint: dict[str, Any] = field(default_factory=dict)
    control_passed: bool = False
    created_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class Hypothesis:
    """A target-specific vulnerability hypothesis."""

    id: str
    target_id: str
    endpoint: str
    method: str
    parameter: str
    auth_state: str
    role: str
    workflow_step: str
    vulnerability_class: str
    exploit_goal: str
    oracle: str
    preconditions: list[str] = field(default_factory=list)
    payload_family: str = ""
    source: str = "manual"
    novelty_score: float = 0.5
    exploitability_score: float = 0.5
    difficulty_score: float = 0.5
    evidence_score: float = 0.0
    status: str = "new"
    attempts: int = 0
    evidence: list[HypothesisEvidence] = field(default_factory=list)
    negative_controls: list[dict[str, Any]] = field(default_factory=list)
    last_error: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class ReportGateResult:
    """Report gate decision for one hypothesis."""

    allowed: bool
    hypothesis_id: str
    status: str
    positive_controls: int
    negative_controls: int
    missing: list[str]


def _clamp01(value: float | str | None) -> float:
    try:
        numeric = float(value if value is not None else 0.0)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, numeric))


def calculate_task_difficulty(factors: DifficultyFactors) -> float:
    """Calculate the practical TDI score from research notes.

    Formula:
    TDI = 0.30*horizon + 0.25*unknowns + 0.20*context_load
          + 0.15*state_complexity + 0.10*tool_risk
    """

    score = (
        0.30 * _clamp01(factors.horizon)
        + 0.25 * _clamp01(factors.unknowns)
        + 0.20 * _clamp01(factors.context_load)
        + 0.15 * _clamp01(factors.state_complexity)
        + 0.10 * _clamp01(factors.tool_risk)
    )
    return round(score, 2)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _hypothesis_from_dict(raw: dict[str, Any]) -> Hypothesis:
    evidence = [
        HypothesisEvidence(
            id=str(item.get("id") or _new_id("ev")),
            evidence_type=str(item.get("evidence_type") or "observation"),
            summary=str(item.get("summary") or ""),
            request=item.get("request") if isinstance(item.get("request"), dict) else {},
            response_fingerprint=(
                item.get("response_fingerprint")
                if isinstance(item.get("response_fingerprint"), dict)
                else {}
            ),
            control_passed=bool(item.get("control_passed")),
            created_at=float(item.get("created_at") or time.time()),
        )
        for item in raw.get("evidence") or []
        if isinstance(item, dict)
    ]
    return Hypothesis(
        id=str(raw.get("id") or _new_id("hyp")),
        target_id=str(raw.get("target_id") or ""),
        endpoint=str(raw.get("endpoint") or ""),
        method=str(raw.get("method") or "GET").upper(),
        parameter=str(raw.get("parameter") or ""),
        auth_state=str(raw.get("auth_state") or ""),
        role=str(raw.get("role") or ""),
        workflow_step=str(raw.get("workflow_step") or ""),
        vulnerability_class=str(raw.get("vulnerability_class") or "other"),
        exploit_goal=str(raw.get("exploit_goal") or ""),
        oracle=str(raw.get("oracle") or ""),
        preconditions=[str(v) for v in raw.get("preconditions") or []],
        payload_family=str(raw.get("payload_family") or ""),
        source=str(raw.get("source") or "manual"),
        novelty_score=_clamp01(raw.get("novelty_score")),
        exploitability_score=_clamp01(raw.get("exploitability_score")),
        difficulty_score=_clamp01(raw.get("difficulty_score")),
        evidence_score=_clamp01(raw.get("evidence_score")),
        status=(
            str(raw.get("status")) if str(raw.get("status")) in VALID_HYPOTHESIS_STATUSES else "new"
        ),
        attempts=max(0, int(raw.get("attempts") or 0)),
        evidence=evidence,
        negative_controls=[v for v in raw.get("negative_controls") or [] if isinstance(v, dict)],
        last_error=str(raw.get("last_error") or ""),
        created_at=float(raw.get("created_at") or time.time()),
        updated_at=float(raw.get("updated_at") or time.time()),
    )


class HypothesisManager:
    """Persistent hypothesis portfolio for one scan runtime directory."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "hypotheses.json"
        self.trajectories_path = self.state_dir / "hypothesis_trajectories.jsonl"
        self._items: dict[str, Hypothesis] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self._items = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._items = {}
            return
        items = raw.get("hypotheses", raw if isinstance(raw, list) else [])
        self._items = {}
        for item in items:
            if isinstance(item, dict):
                hypothesis = _hypothesis_from_dict(item)
                self._items[hypothesis.id] = hypothesis

    def persist(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "hypotheses": [asdict(item) for item in self._items.values()],
        }
        data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self.state_dir),
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        tmp_path.replace(self.path)

    def create_hypothesis(
        self,
        *,
        target_id: str,
        endpoint: str,
        method: str = "GET",
        parameter: str = "",
        auth_state: str = "",
        role: str = "",
        workflow_step: str = "",
        vulnerability_class: str = "other",
        exploit_goal: str = "",
        oracle: str = "",
        preconditions: list[str] | None = None,
        payload_family: str = "",
        source: str = "manual",
        novelty_score: float = 0.5,
        exploitability_score: float = 0.5,
        difficulty_score: float = 0.5,
        evidence_score: float = 0.0,
    ) -> Hypothesis:
        now = time.time()
        hypothesis = Hypothesis(
            id=_new_id("hyp"),
            target_id=target_id,
            endpoint=endpoint,
            method=method.upper(),
            parameter=parameter,
            auth_state=auth_state,
            role=role,
            workflow_step=workflow_step,
            vulnerability_class=vulnerability_class,
            exploit_goal=exploit_goal,
            oracle=oracle,
            preconditions=preconditions or [],
            payload_family=payload_family,
            source=source,
            novelty_score=_clamp01(novelty_score),
            exploitability_score=_clamp01(exploitability_score),
            difficulty_score=_clamp01(difficulty_score),
            evidence_score=_clamp01(evidence_score),
            created_at=now,
            updated_at=now,
        )
        self._items[hypothesis.id] = hypothesis
        self.persist()
        return hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> Hypothesis | None:
        return self._items.get(hypothesis_id)

    def list_hypotheses(self, status: str | None = None) -> list[Hypothesis]:
        items = list(self._items.values())
        if status:
            items = [item for item in items if item.status == status]
        return sorted(items, key=lambda item: item.updated_at, reverse=True)

    def record_evidence(
        self,
        hypothesis_id: str,
        *,
        evidence_type: str,
        summary: str,
        request: dict[str, Any] | None = None,
        response_fingerprint: dict[str, Any] | None = None,
        control_passed: bool = False,
    ) -> HypothesisEvidence:
        hypothesis = self._require(hypothesis_id)
        evidence = HypothesisEvidence(
            id=_new_id("ev"),
            evidence_type=evidence_type,
            summary=summary,
            request=request or {},
            response_fingerprint=response_fingerprint or {},
            control_passed=control_passed,
        )
        hypothesis.evidence.append(evidence)
        hypothesis.attempts += 1
        if evidence_type == "positive_control" and control_passed:
            hypothesis.evidence_score = max(hypothesis.evidence_score, 0.7)
        elif evidence_type == "negative_control" and control_passed:
            hypothesis.evidence_score = max(hypothesis.evidence_score, 0.8)
        hypothesis.updated_at = time.time()
        self.persist()
        return evidence

    def mark_status(self, hypothesis_id: str, status: str, last_error: str = "") -> Hypothesis:
        if status not in VALID_HYPOTHESIS_STATUSES:
            raise ValueError(
                f"Invalid hypothesis status '{status}'. Expected one of: "
                f"{', '.join(sorted(VALID_HYPOTHESIS_STATUSES))}",
            )
        hypothesis = self._require(hypothesis_id)
        hypothesis.status = status
        hypothesis.last_error = last_error
        hypothesis.updated_at = time.time()
        self.persist()
        return hypothesis

    def score_hypothesis(
        self,
        hypothesis_id: str,
        *,
        novelty_score: float | None = None,
        exploitability_score: float | None = None,
        difficulty_score: float | None = None,
        evidence_score: float | None = None,
    ) -> Hypothesis:
        hypothesis = self._require(hypothesis_id)
        if novelty_score is not None:
            hypothesis.novelty_score = _clamp01(novelty_score)
        if exploitability_score is not None:
            hypothesis.exploitability_score = _clamp01(exploitability_score)
        if difficulty_score is not None:
            hypothesis.difficulty_score = _clamp01(difficulty_score)
        if evidence_score is not None:
            hypothesis.evidence_score = _clamp01(evidence_score)
        hypothesis.updated_at = time.time()
        self.persist()
        return hypothesis

    def select_next_hypothesis(self) -> Hypothesis | None:
        candidates = [
            item for item in self._items.values() if item.status in ACTIVE_HYPOTHESIS_STATUSES
        ]
        if not candidates:
            return None
        return max(candidates, key=self._selection_score)

    def report_gate(self, hypothesis_id: str) -> ReportGateResult:
        hypothesis = self._items.get(hypothesis_id)
        if hypothesis is None:
            return ReportGateResult(
                allowed=False,
                hypothesis_id=hypothesis_id,
                status="missing",
                positive_controls=0,
                negative_controls=0,
                missing=["validated hypothesis was not found"],
            )
        positives = self._count_controls(hypothesis, "positive_control")
        negatives = self._count_controls(hypothesis, "negative_control")
        missing: list[str] = []
        if hypothesis.status != "validated":
            missing.append("hypothesis status must be validated")
        if positives < 2:
            missing.append("at least two positive controls must pass")
        if negatives < 1:
            missing.append("at least one negative control must pass")
        return ReportGateResult(
            allowed=not missing,
            hypothesis_id=hypothesis_id,
            status=hypothesis.status,
            positive_controls=positives,
            negative_controls=negatives,
            missing=missing,
        )

    def store_trajectory(self, hypothesis_id: str, result: str) -> dict[str, Any]:
        hypothesis = self._require(hypothesis_id)
        payload = {
            "target_id": hypothesis.target_id,
            "surface_signature": self._surface_signature(hypothesis),
            "vulnerability_class": hypothesis.vulnerability_class,
            "steps": [asdict(ev) for ev in hypothesis.evidence],
            "result": result,
            "created_at": time.time(),
        }
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with self.trajectories_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        self._store_cross_scan_trajectory(hypothesis, payload)
        return payload

    def search_reusable_trajectories(
        self,
        *,
        target_id: str = "",
        vulnerability_class: str = "",
        endpoint_pattern: str = "",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if self.trajectories_path.exists():
            for line in self.trajectories_path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if vulnerability_class and item.get("vulnerability_class") != vulnerability_class:
                    continue
                if target_id and item.get("target_id") != target_id:
                    continue
                if endpoint_pattern and endpoint_pattern not in json.dumps(item):
                    continue
                results.append(item)
        return results[-limit:]

    def _require(self, hypothesis_id: str) -> Hypothesis:
        hypothesis = self._items.get(hypothesis_id)
        if hypothesis is None:
            raise KeyError(f"Unknown hypothesis_id: {hypothesis_id}")
        return hypothesis

    @staticmethod
    def _count_controls(hypothesis: Hypothesis, evidence_type: str) -> int:
        return sum(
            1
            for item in hypothesis.evidence
            if item.evidence_type == evidence_type and item.control_passed
        )

    @staticmethod
    def _selection_score(hypothesis: Hypothesis) -> float:
        return (
            0.35 * hypothesis.evidence_score
            + 0.30 * hypothesis.exploitability_score
            + 0.20 * hypothesis.novelty_score
            + 0.15 * (1.0 - hypothesis.difficulty_score)
            - min(0.3, hypothesis.attempts * 0.03)
        )

    @staticmethod
    def _surface_signature(hypothesis: Hypothesis) -> str:
        raw = (
            f"{hypothesis.endpoint}|{hypothesis.method}|{hypothesis.parameter}|"
            f"{hypothesis.auth_state}|{hypothesis.role}|{hypothesis.workflow_step}|"
            f"{hypothesis.vulnerability_class}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _store_cross_scan_trajectory(
        hypothesis: Hypothesis,
        payload: dict[str, Any],
    ) -> None:
        try:
            category = (
                "successful_technique"
                if payload.get("result") == "validated"
                else "failed_approach"
            )
            KnowledgeStore().store(
                domain=hypothesis.target_id,
                category=category,
                key=f"{hypothesis.vulnerability_class}:{hypothesis.endpoint}:{hypothesis.parameter}",
                value=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                confidence=0.85 if category == "successful_technique" else 0.65,
                source="hypothesis_trajectory",
                scan_id=None,
            )
        except Exception:  # noqa: BLE001
            return


_active_manager: HypothesisManager | None = None


def hydrate_hypotheses_from_disk(state_dir: Path | str) -> None:
    """Initialize the active scan hypothesis manager."""

    global _active_manager  # noqa: PLW0603
    _active_manager = HypothesisManager(state_dir)


def get_active_hypothesis_manager() -> HypothesisManager | None:
    """Return the active scan hypothesis manager if one has been hydrated."""

    return _active_manager


def require_active_hypothesis_manager() -> HypothesisManager:
    """Return the active manager or raise a clear runtime error."""

    if _active_manager is None:
        raise RuntimeError(
            "HypothesisManager not initialised — call hydrate_hypotheses_from_disk first",
        )
    return _active_manager
