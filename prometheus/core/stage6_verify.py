"""Stage 6 — adversarial verification of candidates.

Promotes ``verify_finding`` from a tool (mid-conversation) to a separate
stage with its own model role. Returns ``TRUE_POSITIVE`` /
``FALSE_POSITIVE`` + CVSS 3.1 vector.

This module is *deterministic verification*: it re-checks the candidate
against rules (replay the request, check the response, compare to
known-FP classes) without a fresh LLM call. The runner is expected to
optionally layer an LLM verifier on top (see
:func:`llm_verify_candidate`) but the deterministic check is the
ground truth.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from prometheus.core.always_rejected import match_rejection
from prometheus.core.conditionally_valid import conditionally_valid
from prometheus.core.seven_question_gate import run_gate

logger = logging.getLogger(__name__)


_VERDICT_TP = "TRUE_POSITIVE"
_VERDICT_FP = "FALSE_POSITIVE"
_VERDICT_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class VerifyResult:
    candidate_id: str
    verdict: str
    cvss_vector: str | None
    cvss_score: float | None
    reason: str
    evidence_refs: list[str] = field(default_factory=list)
    chain_id: str | None = None
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "verdict": self.verdict,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "chain_id": self.chain_id,
            "duration_s": self.duration_s,
        }


# CVSS 3.1 lookup for a small set of v1 vuln classes.
_CVSS_VECTORS: dict[str, tuple[str, float]] = {
    "sqli": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "rce": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "ssrf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L", 8.0),
    "idor": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "auth_bypass": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "account_enumeration": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    "cors": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.6),
    "exposed_unauthenticated": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "source_map": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
}


def _cvss_for(vuln_type: str) -> tuple[str, float] | None:
    return _CVSS_VECTORS.get(str(vuln_type or "").lower().strip())


def _extract_replay_request(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Return a dict suitable for httpx replay: method, url, headers, body."""
    request = candidate.get("request") or candidate.get("replay_request")
    if isinstance(request, dict):
        return request
    if isinstance(request, str) and request.strip():
        # Parse "GET /path HTTP/1.1" style
        m = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", request, re.IGNORECASE)
        if m:
            return {"method": m.group(1).upper(), "url": m.group(2)}
    url = candidate.get("url") or candidate.get("endpoint")
    if url and isinstance(url, str) and urlparse(url).netloc:
        return {"method": "GET", "url": url}
    return None


async def deterministic_verify_candidate(
    candidate: dict[str, Any],
    *,
    timeout_s: float = 15.0,
) -> VerifyResult:
    """Run the deterministic verifier on a single candidate.

    Steps (in order):
    1. Always-rejected class without a chain → FP.
    2. Chain-validated → TP.
    3. 7-Question Gate KILL → FP.
    4. Otherwise → INCONCLUSIVE (caller may layer an LLM verifier).
    """
    cid = str(candidate.get("id") or candidate.get("candidate_id") or "?")
    started = datetime.now(UTC).timestamp()

    rule = match_rejection(candidate)
    if rule is not None:
        chain = conditionally_valid(candidate)
        if chain is None:
            return VerifyResult(
                candidate_id=cid,
                verdict=_VERDICT_FP,
                cvss_vector=None,
                cvss_score=None,
                reason=f"always-rejected class {rule.id!r}; no chain",
                duration_s=datetime.now(UTC).timestamp() - started,
            )
    gate = run_gate(candidate)
    if gate.killed:
        return VerifyResult(
            candidate_id=cid,
            verdict=_VERDICT_FP,
            cvss_vector=None,
            cvss_score=None,
            reason=f"gate {gate.outcome.value}: {gate.reason}",
            duration_s=datetime.now(UTC).timestamp() - started,
        )
    if gate.passed:
        cvss = _cvss_for(candidate.get("vuln_type", ""))
        return VerifyResult(
            candidate_id=cid,
            verdict=_VERDICT_TP,
            cvss_vector=cvss[0] if cvss else None,
            cvss_score=cvss[1] if cvss else None,
            reason=gate.reason,
            chain_id=gate.chain_id,
            duration_s=datetime.now(UTC).timestamp() - started,
        )
    return VerifyResult(
        candidate_id=cid,
        verdict=_VERDICT_INCONCLUSIVE,
        cvss_vector=None,
        cvss_score=None,
        reason=f"gate {gate.outcome.value}: {gate.reason}",
        duration_s=datetime.now(UTC).timestamp() - started,
    )


async def replay_request(
    candidate: dict[str, Any], *, timeout_s: float = 15.0
) -> dict[str, Any] | None:
    """Best-effort replay of the candidate's original request.

    Returns ``{"status": int, "body": str, "headers": dict}`` or ``None``
    when the request cannot be replayed. Used by the LLM verifier to
    compare a fresh response to the candidate's evidence.
    """
    req = _extract_replay_request(candidate)
    if not req:
        return None
    method = str(req.get("method", "GET")).upper()
    url = req.get("url")
    if not url:
        return None
    headers = dict(req.get("headers") or {})
    body = req.get("body")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout_s) as client:
            r = await client.request(method, url, headers=headers, content=body)
        return {
            "status": r.status_code,
            "body": r.text[:_MAX_REPLAY_BODY],
            "headers": {k: v for k, v in r.headers.items()},
        }
    except httpx.HTTPError as exc:
        logger.debug("Replay failed for %s: %s", cid_hint(candidate), exc)
        return None


_MAX_REPLAY_BODY = 4096


def cid_hint(candidate: dict[str, Any]) -> str:
    return str(candidate.get("id") or candidate.get("candidate_id") or "?")


async def verify_candidate(
    candidate: dict[str, Any],
    *,
    use_llm: bool = False,
) -> VerifyResult:
    """Public entrypoint.

    Runs the deterministic verifier. When ``use_llm`` is True, an
    LLM-based verifier is layered on top (placeholder: the deterministic
    result wins; an upstream LLM hook can override).
    """
    result = await deterministic_verify_candidate(candidate)
    if not use_llm or result.verdict != _VERDICT_INCONCLUSIVE:
        return result
    # Inconclusive + LLM requested — the runner can override by calling
    # the LLM verifier separately. The deterministic verifier is the
    # source of truth.
    return result


__all__ = [
    "VerifyResult",
    "deterministic_verify_candidate",
    "replay_request",
    "verify_candidate",
]
