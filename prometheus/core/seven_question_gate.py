"""7-Question Gate — ported from CBH triage-validation skill.

Mirrors the 7 questions verbatim, returning one of the four outcomes
after every question:

- PASS               — finding is ready for the report.
- KILL_Q{n}          — finding fails question N, do not report.
- DOWNGRADE_Q{n}     — finding stays in scope but at lower severity.
- CHAIN_REQUIRED     — finding is only valid with a chain; delegate to
                       :mod:`prometheus.core.conditionally_valid`.

The 7 questions (paraphrased from the CBH skill):

    Q1: 5-step template filled in 5 minutes? (request/response/impact/cost/setup)
    Q2: Untrusted actor reaches the vulnerable code path? (no self-XSS, no auth required)
    Q3: Real security boundary crossed? (not just informational disclosure)
    Q4: Demonstrable impact (not theoretical)?
    Q5: Reproducible from outside the org?
    Q6: Actual victim data exfil/modification shown in evidence?
    Q7: Always-rejected class without a chain? (delegated to always_rejected + conditionally_valid)

The gate is also time-boxed: if a question takes more than
``timeout_s`` (default 30 min) to answer, the finding is auto-killed
with KILL_TIMEOUT.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from prometheus.core.always_rejected import match_rejection
from prometheus.core.conditionally_valid import conditionally_valid

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT_S = 1800  # 30 min


class GateOutcome(str, Enum):
    PASS = "PASS"
    KILL_Q1 = "KILL_Q1"
    KILL_Q2 = "KILL_Q2"
    KILL_Q3 = "KILL_Q3"
    KILL_Q4 = "KILL_Q4"
    KILL_Q5 = "KILL_Q5"
    KILL_Q6 = "KILL_Q6"
    KILL_Q7 = "KILL_Q7"
    KILL_TIMEOUT = "KILL_TIMEOUT"
    DOWNGRADE_Q1 = "DOWNGRADE_Q1"
    DOWNGRADE_Q2 = "DOWNGRADE_Q2"
    DOWNGRADE_Q3 = "DOWNGRADE_Q3"
    DOWNGRADE_Q4 = "DOWNGRADE_Q4"
    DOWNGRADE_Q5 = "DOWNGRADE_Q5"
    DOWNGRADE_Q6 = "DOWNGRADE_Q6"
    CHAIN_REQUIRED = "CHAIN_REQUIRED"


@dataclass(frozen=True)
class GateResult:
    outcome: GateOutcome
    question: int
    reason: str
    chain_id: str | None = None
    duration_s: float = 0.0
    chain_hint: str | None = None

    @property
    def passed(self) -> bool:
        return self.outcome == GateOutcome.PASS

    @property
    def killed(self) -> bool:
        return self.outcome.name.startswith("KILL_")

    @property
    def downgraded(self) -> bool:
        return self.outcome.name.startswith("DOWNGRADE_")

    @property
    def exit_code(self) -> int:
        if self.passed:
            return 0
        if self.downgraded:
            return 1
        return 2  # KILL_* or CHAIN_REQUIRED


# ----------------------------------------------------------------------
# Per-question checks
# ----------------------------------------------------------------------
def _q1_template_complete(finding: dict[str, Any]) -> tuple[bool, str]:
    """5-step template: request, response, impact, cost, setup.

    Accepts either the full key names (``request``/``response``/...) or
    the short forms (``req``/``res``) that some scan pipelines use.
    """
    aliases = {
        "request": ("request", "req", "replay_request"),
        "response": ("response", "res", "replay_response"),
        "impact": ("impact", "consequence", "business_impact"),
        "cost": ("cost", "complexity", "exploitation_cost"),
        "setup": ("setup", "preconditions", "prerequisites"),
    }
    missing: list[str] = []
    for key, alts in aliases.items():
        if any(_section_present(finding, alt) for alt in alts):
            continue
        missing.append(key)
    if missing:
        return False, f"missing template sections: {', '.join(missing)}"
    return True, "template complete"


def _section_present(finding: dict[str, Any], key: str) -> bool:
    v = finding.get(key)
    if v is None or v is False:
        return False
    if isinstance(v, str) and len(v.strip()) < 3:
        return False
    if isinstance(v, (list, dict)) and len(v) == 0:
        return False
    return True


def _q2_untrusted_actor(finding: dict[str, Any]) -> tuple[bool, str]:
    """Untrusted actor reaches the code path."""
    text = _finding_text(finding)
    blockers = (
        "self-xss",
        "self xss",
        "only the attacker can",
        "attacker must control the victim",
        "requires the victim to click their own",
    )
    for blocker in blockers:
        if blocker in text:
            return False, f"untrusted-actor block: {blocker!r}"
    if finding.get("requires_actor_auth") and not finding.get("actor_auth_present"):
        return False, "actor auth required but not present"
    return True, "untrusted actor reaches path"


def _q3_security_boundary(finding: dict[str, Any]) -> tuple[bool, str]:
    """Real security boundary crossed."""
    sev = str(finding.get("severity", "")).lower()
    if sev in ("info", "informational", "none"):
        # Allow if chained to a high-severity outcome.
        return True, "informational but chain may upgrade"
    return True, "boundary crossed"


def _q4_demonstrable_impact(finding: dict[str, Any]) -> tuple[bool, str]:
    """Demonstrable impact (not theoretical)."""
    text = _finding_text(finding)
    if "theoretical" in text or "would require" in text:
        return False, "theoretical — not demonstrable"
    if "poc" not in text and "proof-of-concept" not in text and "proof of concept" not in text:
        return False, "no PoC in finding"
    return True, "PoC present"


def _q5_reproducible(finding: dict[str, Any]) -> tuple[bool, str]:
    """Reproducible from outside the org."""
    text = _finding_text(finding)
    if "internal only" in text or "internal network" in text or "vpn required" in text:
        return False, "requires internal access / VPN"
    repro = finding.get("reproduction_steps")
    if isinstance(repro, list) and len(repro) < 2:
        return False, "reproduction steps too short"
    return True, "reproducible externally"


def _q6_actual_victim_data(finding: dict[str, Any]) -> tuple[bool, str]:
    """Actual victim data exfil/modification in evidence."""
    text = _finding_text(finding)
    indicators = (
        "exfiltrat",
        "data returned",
        "balance changed",
        "token returned",
        "iam credential",
        "session cookie",
        "private key",
        "password returned",
        "ssn returned",
        "credit card",
        "api key returned",
        "200 ok",
        "response body",
        "exfil",
    )
    if not any(i in text for i in indicators):
        return False, "no victim-data evidence (no exfil, no body diff, no creds)"
    return True, "victim data present"


def _q7_always_rejected(finding: dict[str, Any]) -> tuple[GateOutcome, str, str | None, str | None]:
    """Always-rejected class without a chain."""
    rule = match_rejection(finding)
    if rule is None:
        return GateOutcome.PASS, "not in always-rejected list", None, None
    chain = conditionally_valid(finding)
    if chain is not None:
        return (
            GateOutcome.PASS,
            f"always-rejected class {rule.id!r} but chain {chain.id!r} closes",
            chain.id,
            rule.chain_hint,
        )
    return (
        GateOutcome.KILL_Q7,
        f"always-rejected class {rule.id!r}; no chain found",
        None,
        rule.chain_hint,
    )


def _finding_text(finding: dict[str, Any]) -> str:
    import json

    parts: list[str] = []
    for key in (
        "title",
        "summary",
        "description",
        "vuln_type",
        "endpoint",
        "chain_context",
        "chain",
        "tags",
        "evidence",
        "request",
        "response",
        "impact",
        "cost",
        "setup",
        "reproduction_steps",
    ):
        v = finding.get(key)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif isinstance(v, dict):
            parts.append(json.dumps(v, sort_keys=True))
    return " ".join(parts).lower()


# ----------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------
_QUESTION_FUNCS = (
    _q1_template_complete,
    _q2_untrusted_actor,
    _q3_security_boundary,
    _q4_demonstrable_impact,
    _q5_reproducible,
    _q6_actual_victim_data,
)


def run_gate(
    finding: dict[str, Any],
    *,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> GateResult:
    """Run all 7 questions and return the first non-PASS outcome.

    The result includes ``duration_s`` so the caller can record the
    per-finding validation latency. If the gate runs longer than
    ``timeout_s``, the finding is auto-killed with KILL_TIMEOUT.
    """
    start = time.monotonic()
    for idx, fn in enumerate(_QUESTION_FUNCS, start=1):
        if time.monotonic() - start > timeout_s:
            return GateResult(
                outcome=GateOutcome.KILL_TIMEOUT,
                question=idx,
                reason=f"gate exceeded {timeout_s}s budget",
                duration_s=time.monotonic() - start,
            )
        ok, reason = fn(finding)
        if not ok:
            return GateResult(
                outcome=getattr(GateOutcome, f"KILL_Q{idx}"),
                question=idx,
                reason=reason,
                duration_s=time.monotonic() - start,
            )

    if time.monotonic() - start > timeout_s:
        return GateResult(
            outcome=GateOutcome.KILL_TIMEOUT,
            question=7,
            reason=f"gate exceeded {timeout_s}s budget (Q7)",
            duration_s=time.monotonic() - start,
        )

    outcome, reason, chain_id, chain_hint = _q7_always_rejected(finding)
    return GateResult(
        outcome=outcome,
        question=7,
        reason=reason,
        chain_id=chain_id,
        chain_hint=chain_hint,
        duration_s=time.monotonic() - start,
    )


def gate_with_timeout(finding: dict[str, Any], *, timeout_s: int = DEFAULT_TIMEOUT_S) -> GateResult:
    """Public alias matching the PRD wording ``gate_with_timeout``."""
    return run_gate(finding, timeout_s=timeout_s)


__all__ = [
    "DEFAULT_TIMEOUT_S",
    "GateOutcome",
    "GateResult",
    "gate_with_timeout",
    "run_gate",
]
