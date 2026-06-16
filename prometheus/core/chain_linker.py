"""Chain linker — surface candidate chains from an engagement.

Consumes the :data:`prometheus.core.conditionally_valid.list_chains`
table + the agent's running finding list, and returns a list of
proposed chains (each chain links 2+ findings, with a recommended
severity escalation).

Wired into ``create_vulnerability_report``: chains are presented as
separate reportable items, with severity escalated per the chain
rule.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from prometheus.core.conditionally_valid import (
    Chain,
    find_chain_links,
    list_chains,
)


@dataclass
class ProposedChain:
    chain: Chain
    supporting_finding_ids: list[str] = field(default_factory=list)
    coverage: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain.id,
            "title": self.chain.title,
            "severity_when_chained": self.chain.severity_when_chained,
            "description": self.chain.description,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "coverage": {k: list(v) for k, v in self.coverage.items()},
            "notes": list(self.notes),
        }


def _finding_ids(findings: Iterable[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = f.get("id") or f.get("candidate_id") or f.get("title")
        if isinstance(fid, str):
            out.append(fid)
    return out


def _link_coverage(findings: list[dict[str, Any]], chain: Chain) -> dict[str, list[str]]:
    """For each required link, list the finding ids that cover it."""
    from prometheus.core.conditionally_valid import _has_link, _finding_text

    coverage: dict[str, list[str]] = {link: [] for link in chain.links_required}
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = f.get("id") or f.get("title") or "?"
        for link in chain.links_required:
            if _has_link(f, link):
                coverage[link].append(str(fid))
    return coverage


def find_chain_links_in_engagement(
    findings: list[dict[str, Any]],
) -> list[ProposedChain]:
    """Return every proposed chain supported by the given findings.

    A chain is "supported" when at least
    ``len(links_required) - 1`` of its required links are covered
    by the finding texts. The 1-link gap is the linker asking the
    human to fill in the missing piece.
    """
    findings = [f for f in findings if isinstance(f, dict)]
    if not findings:
        return []
    proposed: list[ProposedChain] = []
    for chain in find_chain_links(findings):
        coverage = _link_coverage(findings, chain)
        covered_links = [k for k, v in coverage.items() if v]
        missing = [k for k, v in coverage.items() if not v]
        if not covered_links:
            continue
        notes: list[str] = []
        if missing:
            notes.append(
                f"missing links: {missing}; need a finding that covers them before "
                f"this chain can be reported at {chain.severity_when_chained}"
            )
        proposed.append(
            ProposedChain(
                chain=chain,
                supporting_finding_ids=_finding_ids(findings),
                coverage=coverage,
                notes=notes,
            )
        )
    # Stable order: severity-when-chained then chain id.
    proposed.sort(key=lambda p: (p.chain.severity_when_chained, p.chain.id))
    return proposed


def all_known_chain_ids() -> list[str]:
    """Return the list of known chain IDs (for tests + UI)."""
    return [c.id for c in list_chains()]


__all__ = [
    "ProposedChain",
    "all_known_chain_ids",
    "find_chain_links_in_engagement",
]
