"""Prometheus eval framework — skills-on vs skills-off ablation.

Long-term, this lives in a separate ``prometheus-eval/`` repo. For
the in-tree change 4.4, this module ships the lightweight harness:

- :class:`EvalChallenge` — a single test (target + vuln class + expected
  finding class).
- :func:`run_eval` — runs each challenge against an oracle (the
  Prometheus pipeline, in baseline or conditions-skills mode) and
  records pass/fail + per-run timing + token cost.

The challenges themselves live in :mod:`prometheus.eval.challenges`;
the oracles are pluggable.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable


@dataclass
class EvalChallenge:
    """A single eval test: target + expected outcome."""

    id: str
    target: str
    vuln_class: str
    expected_severity: str = "P3"
    expected_chain: str | None = None
    description: str = ""
    tags: list[str] = field(default_factory=list)
    timeout_s: int = 600

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvalResult:
    challenge_id: str
    passed: bool
    found_class: str | None
    found_severity: str | None
    found_chain: str | None
    duration_s: float
    cost_usd: float
    turns: int
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Pluggable oracle type. The real implementation will be a thin
# wrapper around the Prometheus CLI; the eval framework does not
# care how the oracle works, only whether it returned the right
# finding class.
OracleFn = Callable[[EvalChallenge], EvalResult]


# ----------------------------------------------------------------------
# Sample challenge corpus
# ----------------------------------------------------------------------
SAMPLE_CHALLENGES: list[EvalChallenge] = [
    EvalChallenge(
        id="juiceshop-login-bendersql",
        target="http://localhost:3000/rest/user/login",
        vuln_class="sqli",
        expected_severity="P0",
        description="SQLi in OWASP Juice Shop /rest/user/login (email param)",
        tags=["juice-shop", "sqli", "auth-bypass"],
    ),
    EvalChallenge(
        id="juiceshop-basket-idor",
        target="http://localhost:3000/rest/continue-code/apply/",
        vuln_class="idor",
        expected_severity="P2",
        description="IDOR on Juice Shop basket / continue-code",
        tags=["juice-shop", "idor"],
    ),
    EvalChallenge(
        id="portswigger-lab-apiracle",
        target="https://portswigger.net/web-security/api-testing/lab-exploiting-hidden-api-endpoint",
        vuln_class="exposed_unauthenticated",
        expected_severity="P1",
        description="Hidden API endpoint lab (PortSwigger Academy)",
        tags=["portswigger", "broken-access-control"],
    ),
]


# ----------------------------------------------------------------------
# Mock oracle (used by the in-tree harness; replaced by the real CLI
# wrapper in ``prometheus-eval/``)
# ----------------------------------------------------------------------
def mock_oracle(challenge: EvalChallenge) -> EvalResult:
    """A trivial oracle that "solves" the first challenge of the
    sample corpus and fails everything else. Replace with the real
    CLI wrapper for actual measurements.
    """
    start = time.monotonic()
    if challenge.id == "juiceshop-login-bendersql":
        return EvalResult(
            challenge_id=challenge.id,
            passed=True,
            found_class="sqli",
            found_severity="P0",
            found_chain=None,
            duration_s=time.monotonic() - start,
            cost_usd=0.0,
            turns=0,
            notes="mock — pass",
        )
    return EvalResult(
        challenge_id=challenge.id,
        passed=False,
        found_class=None,
        found_severity=None,
        found_chain=None,
        duration_s=time.monotonic() - start,
        cost_usd=0.0,
        turns=0,
        notes="mock — not implemented",
    )


# ----------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------
def run_eval(
    challenges: Iterable[EvalChallenge],
    oracle: OracleFn,
    *,
    conditions_skills: bool = False,
) -> dict[str, Any]:
    """Run each challenge and return aggregate stats + per-challenge rows.

    Args:
        challenges: the test corpus.
        oracle: pluggable oracle (the Prometheus CLI wrapper, or the
            mock for unit tests).
        conditions_skills: whether to enable the skills-on condition.
            In the real framework this is an env var (e.g.,
            ``PROMETHEUS_SKILLS=1``).
    """
    results: list[EvalResult] = []
    for ch in challenges:
        try:
            r = oracle(ch)
        except Exception as exc:  # pragma: no cover - defensive
            r = EvalResult(
                challenge_id=ch.id,
                passed=False,
                found_class=None,
                found_severity=None,
                found_chain=None,
                duration_s=0.0,
                cost_usd=0.0,
                turns=0,
                notes=f"oracle crashed: {exc!r}",
            )
        results.append(r)
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    per_class: dict[str, dict[str, int]] = {}
    for r, ch in zip(results, list(challenges)):
        bucket = per_class.setdefault(ch.vuln_class, {"total": 0, "passed": 0})
        bucket["total"] += 1
        if r.passed:
            bucket["passed"] += 1
    return {
        "conditions_skills": conditions_skills,
        "total": total,
        "passed": passed,
        "pass_rate": (passed / total) if total else 0.0,
        "per_class": per_class,
        "results": [r.to_dict() for r in results],
    }


def write_eval_report(report: dict[str, Any], dest: str | Path) -> Path:
    """Write the eval report to disk as JSON."""
    import os

    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    return path


__all__ = [
    "EvalChallenge",
    "EvalResult",
    "OracleFn",
    "SAMPLE_CHALLENGES",
    "mock_oracle",
    "run_eval",
    "write_eval_report",
]
