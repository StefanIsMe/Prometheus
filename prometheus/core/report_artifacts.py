"""Versioned submission artifact generation from stored evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from prometheus.core.candidate_store import CandidateStore

_DEFAULT_ARTIFACT_ROOT = Path.home() / ".prometheus" / "artifacts"


def generate_submission_artifacts(
    finding_id: str,
    *,
    platform: str = "hackerone",
    artifact_root: Path | str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Generate reproducible report artifacts from DB evidence only."""
    store = CandidateStore(db_path)
    candidate = store.get_candidate(finding_id)
    if not candidate:
        raise ValueError(f"Finding candidate not found: {finding_id}")
    evidence = store.list_evidence(finding_id)
    if not evidence:
        raise ValueError("Cannot generate report artifacts without stored evidence")

    root = Path(artifact_root) if artifact_root else _DEFAULT_ARTIFACT_ROOT
    version = store.next_artifact_version(finding_id, platform, "report_markdown")
    out_dir = (
        root / _safe_name(str(candidate.get("domain") or "unknown")) / finding_id / f"v{version}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    bundle = {
        "candidate": candidate,
        "evidence": evidence,
        "validation_runs": store.list_validation_runs(finding_id),
    }

    files: dict[str, Path] = {}
    files["report_markdown"] = out_dir / "report.md"
    files["report_markdown"].write_text(
        _render_report_markdown(candidate, evidence), encoding="utf-8"
    )

    if platform == "bugcrowd":
        files["bugcrowd_json"] = out_dir / "bugcrowd.json"
        files["bugcrowd_json"].write_text(
            json.dumps(_render_bugcrowd_json(candidate, evidence), indent=2), encoding="utf-8"
        )
    else:
        files["h1_markdown"] = out_dir / "hackerone.md"
        files["h1_markdown"].write_text(_render_h1_markdown(candidate, evidence), encoding="utf-8")

    files["poc_script"] = out_dir / "poc.sh"
    files["poc_script"].write_text(_render_poc_script(candidate, evidence), encoding="utf-8")

    files["evidence_bundle"] = out_dir / "evidence_bundle.json"
    files["evidence_bundle"].write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )

    artifacts: list[dict[str, Any]] = []
    for artifact_type, path in files.items():
        digest = _sha256(path)
        result = store.add_submission_artifact(
            finding_id=finding_id,
            platform=platform,
            artifact_type=artifact_type,
            path=str(path),
            sha256=digest,
        )
        artifacts.append(
            {
                "artifact_type": artifact_type,
                "path": str(path),
                "sha256": digest,
                "version": result["version"],
            }
        )

    return {
        "success": True,
        "finding_id": finding_id,
        "platform": platform,
        "version": version,
        "directory": str(out_dir),
        "artifacts": artifacts,
    }


def _render_report_markdown(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    lines = [
        f"# {candidate.get('title')}",
        "",
        f"Domain: {candidate.get('domain')}",
        f"Status: {candidate.get('lifecycle_status')}",
        f"Severity: {candidate.get('severity') or 'unknown'}",
        f"Type: {candidate.get('vuln_type')}",
        f"Endpoint: {candidate.get('endpoint') or 'N/A'}",
        "",
        "## Evidence",
    ]
    for item in evidence:
        lines.extend(
            [
                "",
                f"### {item.get('evidence_kind')} {item.get('id')}",
                str(item.get("summary") or ""),
            ]
        )
        if item.get("path"):
            lines.append(f"Path: {item['path']}")
        if item.get("inline_json"):
            lines.extend(["", "```json", _pretty_json(item["inline_json"]), "```"])
    return "\n".join(lines) + "\n"


def _render_h1_markdown(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    return "\n".join(
        [
            f"# {candidate.get('title')}",
            "",
            "## Summary",
            f"{candidate.get('vuln_type')} on {candidate.get('endpoint') or candidate.get('domain')}",
            "",
            "## Impact",
            _impact_from_evidence(evidence),
            "",
            "## Steps to Reproduce",
            _steps_from_evidence(evidence),
            "",
            "## Evidence",
            _render_report_markdown(candidate, evidence),
        ]
    )


def _render_bugcrowd_json(
    candidate: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "title": candidate.get("title"),
        "target": candidate.get("domain"),
        "vulnerability_type": candidate.get("vuln_type"),
        "severity": candidate.get("severity"),
        "endpoint": candidate.get("endpoint"),
        "description": _render_report_markdown(candidate, evidence),
    }


def _render_poc_script(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    commands: list[str] = []
    for item in evidence:
        text = " ".join(
            str(item.get(key) or "") for key in ("summary", "inline_json", "metadata_json")
        )
        commands.extend(re.findall(r"curl\s+[^\n]+", text))
    if not commands:
        endpoint = candidate.get("endpoint") or candidate.get("domain") or ""
        commands.append(f"curl -i {endpoint}")
    return "#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(commands) + "\n"


def _impact_from_evidence(evidence: list[dict[str, Any]]) -> str:
    text = "\n".join(str(item.get("summary") or "") for item in evidence if item.get("summary"))
    return text or "Impact is shown in the stored request and response evidence."


def _steps_from_evidence(evidence: list[dict[str, Any]]) -> str:
    lines = []
    for idx, item in enumerate(evidence, 1):
        lines.append(
            f"{idx}. Review {item.get('evidence_kind')} evidence: {item.get('summary') or item.get('id')}"
        )
    return "\n".join(lines)


def _pretty_json(raw: Any) -> str:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)
    except Exception:
        return str(raw)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_") or "unknown"
