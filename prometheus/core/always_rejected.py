"""Always-Rejected matrix — ported from CBH triage-validation skill.

The 7-Question Gate (Change 1.3) consults :func:`match_rejection` on Q7
("Is this an always-rejected class without a chain?"). If a finding's
title or evidence matches an always-rejected rule, the gate returns
``KILL_Q7`` with the matching rule's ``rejection_reason``.

A finding that is *always-rejected* but has a chain (e.g. open redirect
+ OAuth) is NOT rejected by this module; :mod:`prometheus.core.conditionally_valid`
handles chain detection.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


_DATA_FILE = Path(__file__).resolve().parent.parent / "skills" / "data" / "always_rejected.json"


@dataclass(frozen=True)
class RejectionRule:
    id: str
    title_patterns: tuple[str, ...]
    description: str
    rejection_reason: str
    severity: str
    requires_chain: bool
    chain_hint: str | None


@lru_cache(maxsize=1)
def _load_rules() -> tuple[RejectionRule, ...]:
    if not _DATA_FILE.exists():
        logger.warning("always_rejected.json missing at %s; no rules loaded", _DATA_FILE)
        return tuple()
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("always_rejected.json unreadable: %s", exc)
        return tuple()
    rules: list[RejectionRule] = []
    for entry in raw.get("rules", []):
        if not isinstance(entry, dict):
            continue
        rid = str(entry.get("id", "")).strip()
        if not rid:
            continue
        rules.append(
            RejectionRule(
                id=rid,
                title_patterns=tuple(str(p).lower() for p in entry.get("title_match", [])),
                description=str(entry.get("description", "")),
                rejection_reason=str(entry.get("rejection_reason", rid)),
                severity=str(entry.get("severity", "info")),
                requires_chain=bool(entry.get("requires_chain", False)),
                chain_hint=entry.get("chain_hint"),
            )
        )
    return tuple(rules)


def _finding_text(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "title",
        "summary",
        "description",
        "vuln_type",
        "endpoint",
        "request",
        "response",
        "evidence",
        "impact",
    ):
        v = finding.get(key)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(json.dumps(v, sort_keys=True))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(json.dumps(item, sort_keys=True))
    return "\n".join(parts).lower()


def match_rejection(finding: dict[str, Any]) -> RejectionRule | None:
    """Return the first always-rejected rule that matches, or None.

    Matching is a case-insensitive substring scan across the finding's
    text fields. Regex is intentionally avoided to keep the data file
    portable and human-editable.
    """
    text = _finding_text(finding)
    if not text:
        return None
    for rule in _load_rules():
        for pat in rule.title_patterns:
            if pat and pat in text:
                return rule
    return None


def list_rules() -> tuple[RejectionRule, ...]:
    """Return all loaded rules (for tests + the gate UI)."""
    return _load_rules()


__all__ = ["RejectionRule", "match_rejection", "list_rules"]
