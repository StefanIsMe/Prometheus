"""N-run LLM voting — VVAH ``s4 deepdive`` + ``s5 prefilter`` pattern.

Run the deep-dive agent N times with ``temperature > 0`` per chunk.
Group findings by ``(vuln_type, endpoint, parameter, auth_state)``.
Drop findings whose vote count is below ``vote_threshold``. Keep
``validation_judge.py`` as a post-vote heuristic (per PRD).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VoteConfig:
    runs: int = 3
    vote_threshold: int = 2
    parallel: bool = True
    temperature: float = 0.7


@dataclass
class VotedFinding:
    """A finding after N-run voting consolidation."""

    key: tuple[str, str, str, str]
    vuln_type: str
    endpoint: str
    parameter: str
    auth_state: str
    votes: int = 0
    runs_present: list[int] = field(default_factory=list)
    payloads: list[dict[str, Any]] = field(default_factory=list)
    sample: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "auth_state": self.auth_state,
            "votes": self.votes,
            "runs_present": list(self.runs_present),
            "sample": self.sample,
        }


def _normalize_auth_state(finding: dict[str, Any]) -> str:
    """Return an auth-state token (anonymous/authenticated/admin) for grouping."""
    text = (finding.get("auth_state") or finding.get("vuln_type") or "").lower()
    if "admin" in text:
        return "admin"
    if "auth" in text or "logged" in text or "user" in text:
        return "authenticated"
    return "anonymous"


def _finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(finding.get("vuln_type", "")).lower().strip(),
        str(finding.get("endpoint", finding.get("url", ""))).lower().strip(),
        str(finding.get("parameter", finding.get("param", ""))).lower().strip(),
        _normalize_auth_state(finding),
    )


def consolidate_votes(
    run_results: Iterable[list[dict[str, Any]]],
    *,
    config: VoteConfig | None = None,
) -> tuple[list[VotedFinding], list[VotedFinding]]:
    """Take N lists of findings (one per run) and return (kept, dropped).

    A finding is *kept* if it appears in ``>= vote_threshold`` runs and
    has the same ``(vuln_type, endpoint, parameter, auth_state)`` key.
    Returns the kept list and the dropped list for telemetry.
    """
    cfg = config or VoteConfig()
    grouped: dict[tuple[str, str, str, str], VotedFinding] = {}
    for run_idx, findings in enumerate(run_results):
        seen_keys_in_run: set[tuple[str, str, str, str]] = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            key = _finding_key(f)
            entry = grouped.get(key)
            if entry is None:
                entry = VotedFinding(
                    key=key,
                    vuln_type=key[0],
                    endpoint=key[1],
                    parameter=key[2],
                    auth_state=key[3],
                )
                grouped[key] = entry
            if key in seen_keys_in_run:
                # Same finding appeared twice in one run; only count once.
                continue
            seen_keys_in_run.add(key)
            entry.votes += 1
            entry.runs_present.append(run_idx)
            entry.payloads.append(f)
            entry.sample = entry.sample or f

    kept: list[VotedFinding] = []
    dropped: list[VotedFinding] = []
    for entry in grouped.values():
        if entry.votes >= cfg.vote_threshold:
            kept.append(entry)
        else:
            dropped.append(entry)
    logger.info(
        "n_run_vote: %d unique findings, %d kept (>=%d), %d dropped (runs=%d)",
        len(grouped),
        len(kept),
        cfg.vote_threshold,
        len(dropped),
        cfg.runs,
    )
    return kept, dropped


# Convenience wrapper: an async run_fn that accepts a chunk and returns
# findings. We don't await it here — the runner does that and passes the
# results in.
async def run_n_runs(
    run_fn: Callable[[int, float], list[dict[str, Any]]],
    config: VoteConfig | None = None,
) -> tuple[list[VotedFinding], list[VotedFinding]]:
    """Call ``run_fn(run_idx, temperature)`` ``config.runs`` times, then vote."""
    import asyncio

    cfg = config or VoteConfig()

    async def one(idx: int) -> list[dict[str, Any]]:
        return run_fn(idx, cfg.temperature)

    if cfg.parallel:
        results = await asyncio.gather(*(one(i) for i in range(cfg.runs)))
    else:
        results = []
        for i in range(cfg.runs):
            results.append(await one(i))
    return consolidate_votes(results, config=cfg)


__all__ = [
    "VoteConfig",
    "VotedFinding",
    "consolidate_votes",
    "run_n_runs",
]
