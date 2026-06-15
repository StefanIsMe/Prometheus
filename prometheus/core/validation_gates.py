"""Evidence first validation gates for v1 bug bounty classes."""

from __future__ import annotations

import json
from typing import Any

_REQUIRED_BY_TYPE: dict[str, dict[str, Any]] = {
    "idor": {
        "positive_controls": 2,
        "negative_controls": 1,
        "signals": ["unauthorized", "other user", "cross tenant", "read", "write"],
    },
    "auth_bypass": {
        "positive_controls": 1,
        "negative_controls": 1,
        "signals": ["protected", "without auth", "denied", "bypass"],
    },
    "account_enumeration": {
        "positive_controls": 2,
        "negative_controls": 0,
        "signals": ["differential", "fingerprint", "exists", "not found"],
    },
    "ssrf": {
        "positive_controls": 1,
        "negative_controls": 0,
        "signals": ["internal", "callback", "metadata", "reachability"],
    },
    "cors": {
        "positive_controls": 1,
        "negative_controls": 0,
        "signals": ["readable", "protected", "state changing", "authenticated"],
    },
    "exposed_unauthenticated_endpoint": {
        "positive_controls": 1,
        "negative_controls": 0,
        "signals": ["sensitive", "privileged", "unauthenticated"],
    },
    "source_map_or_bundle_leak": {
        "positive_controls": 1,
        "negative_controls": 0,
        "signals": ["exploit chain", "sensitive", "secret", "endpoint"],
    },
}


def evaluate_validation_gate(
    *,
    vuln_type: str,
    evidence: list[dict[str, Any]],
    validation_runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate stored evidence against hard v1 acceptance gates."""
    normalized_type = vuln_type.lower().strip()
    requirement = _REQUIRED_BY_TYPE.get(normalized_type)
    if requirement is None:
        return {
            "passed": False,
            "reason": f"No v1 validation gate for vuln_type={vuln_type}",
            "missing": ["supported vuln_type"],
        }

    positive = _count_control(evidence, "positive")
    negative = _count_control(evidence, "negative")
    evidence_text = _evidence_text(evidence)
    signals = [signal for signal in requirement["signals"] if signal in evidence_text]
    successful_run = any(
        str(run.get("status") or "").lower() in {"success", "passed", "verified", "completed"}
        for run in (validation_runs or [])
    )

    missing: list[str] = []
    if positive < int(requirement["positive_controls"]):
        missing.append(f"positive_controls>={requirement['positive_controls']}")
    if negative < int(requirement["negative_controls"]):
        missing.append(f"negative_controls>={requirement['negative_controls']}")
    if not signals:
        missing.append("impact_signal")
    if not successful_run:
        missing.append("successful_validation_run")

    return {
        "passed": not missing,
        "reason": "validation gate passed" if not missing else "validation gate failed",
        "missing": missing,
        "positive_controls": positive,
        "negative_controls": negative,
        "signals": signals,
    }


def _count_control(evidence: list[dict[str, Any]], expected: str) -> int:
    count = 0
    for item in evidence:
        kind = str(item.get("evidence_kind") or "").lower()
        text = json.dumps(item, ensure_ascii=False, default=str).lower()
        if kind == "control" and expected in text:
            count += 1
    return count


def _evidence_text(evidence: list[dict[str, Any]]) -> str:
    return json.dumps(evidence, ensure_ascii=False, default=str).lower()
