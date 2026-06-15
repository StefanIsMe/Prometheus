"""SARIF 2.1.0 emission for Prometheus findings.

Defer-to-v2 per the integration plan; this module ships a minimal,
schema-conformant emitter so the rest of the system can be wired
without blocking on real findings.

Schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Prometheus"
TOOL_VERSION = "1.0.0"
DRIVER_RULES: list[dict[str, Any]] = []  # populated lazily on emit


_SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
    "p0": "error",
    "p1": "error",
    "p2": "warning",
    "p3": "note",
    "p4": "note",
}


@dataclass
class SarifResult:
    rule_id: str
    level: str
    message: str
    locations: list[dict[str, Any]] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.level,
            "message": {"text": self.message},
        }
        if self.locations:
            out["locations"] = list(self.locations)
        if self.properties:
            out["properties"] = dict(self.properties)
        return out


def _sarif_level(finding: dict[str, Any]) -> str:
    sev = str(finding.get("severity") or "").strip().lower()
    if not sev:
        cvss = finding.get("cvss_score")
        if isinstance(cvss, (int, float)):
            if cvss >= 9.0:
                return "error"
            if cvss >= 4.0:
                return "warning"
            return "note"
    return _SEVERITY_TO_SARIF_LEVEL.get(sev, "warning")


def _sarif_location(finding: dict[str, Any]) -> dict[str, Any] | None:
    url = finding.get("endpoint") or finding.get("url") or finding.get("target")
    if not isinstance(url, str) or not url:
        return None
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    phys = {
        "artifactLocation": {"uri": url},
    }
    if parsed.scheme and parsed.netloc:
        phys["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
    return {
        "physicalLocation": phys,
    }


def finding_to_result(finding: dict[str, Any]) -> SarifResult:
    """Convert a Prometheus finding to a SARIF result."""
    rule_id = str(
        finding.get("vuln_type") or finding.get("rule_id") or finding.get("id") or "unknown"
    )
    title = str(finding.get("title") or finding.get("summary") or rule_id)
    message = str(finding.get("description") or title)

    properties: dict[str, Any] = {}
    for key in (
        "id",
        "cwe",
        "cvss",
        "cvss_score",
        "cvss_vector",
        "evidence",
        "chain_id",
        "chain_title",
        "engagement",
    ):
        v = finding.get(key)
        if v is not None and v != "":
            properties[key] = v

    location = _sarif_location(finding)
    locations = [location] if location else []
    return SarifResult(
        rule_id=rule_id,
        level=_sarif_level(finding),
        message=message,
        locations=locations,
        properties=properties,
    )


def emit_sarif(
    findings: Iterable[dict[str, Any]],
    *,
    tool_version: str = TOOL_VERSION,
    invocation_start: str | None = None,
    invocation_end: str | None = None,
    source_root: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from the given findings.

    Round-trip safe: :func:`sarif_to_findings` reconstructs the
    finding list (minus any fields not in the SARIF ``properties``).
    """
    start = invocation_start or _dt.datetime.now(_dt.UTC).isoformat()
    end = invocation_end or _dt.datetime.now(_dt.UTC).isoformat()
    results: list[SarifResult] = [finding_to_result(f) for f in findings if isinstance(f, dict)]
    rule_ids = sorted({r.rule_id for r in results})
    rules = [
        {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid.replace("_", " ").title()},
            "fullDescription": {"text": f"Prometheus rule {rid}."},
            "defaultConfiguration": {"level": "warning"},
        }
        for rid in rule_ids
    ]
    document: dict[str, Any] = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": "https://github.com/yourname/prometheus",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": start,
                        "endTimeUtc": end,
                    }
                ],
                "results": [r.to_dict() for r in results],
            }
        ],
    }
    if source_root:
        document["runs"][0]["originalUriBaseIds"] = {
            "%SRCROOT%": {"uri": source_root},
        }
    return document


def write_sarif(
    findings: Iterable[dict[str, Any]],
    dest: str | Path,
    *,
    source_root: str | None = None,
) -> int:
    """Write the SARIF document to ``dest``. Returns the result count."""
    import json
    from os import replace

    document = emit_sarif(findings, source_root=source_root)
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    replace(tmp, path)
    return len(document["runs"][0]["results"])


def sarif_to_findings(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Round-trip: extract a list of finding dicts from a SARIF doc."""
    findings: list[dict[str, Any]] = []
    for run in document.get("runs", []) or []:
        for result in run.get("results", []) or []:
            finding: dict[str, Any] = {
                "rule_id": result.get("ruleId"),
                "severity": result.get("level"),
                "title": result.get("message", {}).get("text", ""),
                "description": result.get("message", {}).get("text", ""),
            }
            props = result.get("properties") or {}
            for key in (
                "id",
                "cwe",
                "cvss",
                "cvss_score",
                "cvss_vector",
                "evidence",
                "chain_id",
                "chain_title",
                "engagement",
            ):
                if key in props:
                    finding[key] = props[key]
            # 'id' is not always in properties; fall back to ruleId.
            finding.setdefault("id", result.get("ruleId"))
            locations = result.get("locations") or []
            if locations:
                uri = (
                    (locations[0].get("physicalLocation") or {})
                    .get("artifactLocation", {})
                    .get("uri")
                )
                if uri:
                    finding["endpoint"] = uri
            findings.append(finding)
    return findings


__all__ = [
    "DRIVER_RULES",
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SarifResult",
    "emit_sarif",
    "finding_to_result",
    "sarif_to_findings",
    "write_sarif",
]
