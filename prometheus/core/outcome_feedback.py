"""Outcome feedback helpers for stricter future triage."""

from __future__ import annotations

from typing import Any

from prometheus.core.candidate_store import CandidateStore


def summarize_outcomes() -> dict[str, Any]:
    return CandidateStore().outcome_summary()


def rejection_hint_for_candidate(candidate: dict[str, Any]) -> str | None:
    """Return a stored rejection hint for a similar candidate, if one exists."""
    store = CandidateStore()
    summary = store.outcome_summary()
    vuln_type = str(candidate.get("vuln_type") or "unknown").lower()
    endpoint = str(candidate.get("endpoint") or "")[:200].lower()
    for rule in summary.get("feedback_rules", []):
        if str(rule.get("vuln_type") or "").lower() != vuln_type:
            continue
        if str(rule.get("endpoint_pattern") or "").lower() != endpoint:
            continue
        rejected = int(rule.get("rejected_count") or 0)
        duplicates = int(rule.get("duplicate_count") or 0)
        accepted = int(rule.get("accepted_count") or 0)
        if rejected + duplicates > accepted:
            return str(
                rule.get("rejection_hint")
                or "Similar past reports were rejected or marked duplicate"
            )
    return None
