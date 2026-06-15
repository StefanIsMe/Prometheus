"""Auto-report generator for prometheus findings.

When a finding is confirmed (accepted / informational), generates a
markdown report and saves it under ~/.prometheus/reports/<domain>/.

Thread-safe singleton pattern — one ``AutoReporter`` per process.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self


logger = logging.getLogger(__name__)

_REPORTS_ROOT = Path.home() / ".prometheus" / "reports"
_COMMS_GLOBAL = Path.home() / ".prometheus" / "comms" / "global"
_REPORTS_SUMMARY = _COMMS_GLOBAL / "reports.json"

_instance: AutoReporter | None = None
_instance_lock = threading.Lock()


class AutoReporter:
    """Singleton that generates markdown reports for confirmed findings.

    Use ``AutoReporter()`` — the singleton pattern guarantees one
    instance per process.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Self:
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            _instance = inst
            return inst

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self._lock = threading.Lock()
        _REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
        _COMMS_GLOBAL.mkdir(parents=True, exist_ok=True)
        logger.info("AutoReporter initialised (%s)", _REPORTS_ROOT)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(self, finding_data: dict[str, Any]) -> str:
        """Generate a markdown report for *finding_data* and save it.

        Returns the path to the generated markdown file.
        """
        finding_id = finding_data.get("id") or finding_data.get("finding_id", "unknown")
        domain = (
            finding_data.get("domain")
            or finding_data.get("target_name")
            or finding_data.get("target_domain")
            or "unknown"
        )
        severity = finding_data.get("severity", "unknown")
        title = finding_data.get("title") or finding_data.get("name", finding_id)
        description = finding_data.get("description") or finding_data.get("details", "")
        evidence = finding_data.get("evidence") or finding_data.get("proof", "")
        remediation = finding_data.get("remediation") or finding_data.get("fix", "")
        url = finding_data.get("url") or finding_data.get("endpoint", "")
        cvss = finding_data.get("cvss_score") or finding_data.get("cvss", "")
        cve = finding_data.get("cve") or finding_data.get("cve_id", "")
        verdict = finding_data.get("h1_likely_outcome") or finding_data.get("verdict", "")
        confidence = finding_data.get("confidence", "")
        scan_id = finding_data.get("scan_id", "")

        now = datetime.now(UTC)

        md = f"""# Vulnerability Report: {title}

- **Generated**: {now.strftime("%Y-%m-%d %H:%M:%S UTC")}
- **Domain**: {domain}
- **Finding ID**: {finding_id}
- **Severity**: {severity}
"""

        if cvss:
            md += f"- **CVSS**: {cvss}\n"
        if cve:
            md += f"- **CVE**: {cve}\n"
        if verdict:
            md += f"- **Predicted HackerOne Outcome**: {verdict}\n"
        if confidence:
            md += f"- **Confidence**: {confidence}\n"
        if scan_id:
            md += f"- **Scan ID**: {scan_id}\n"
        if url:
            md += f"- **URL/Endpoint**: {url}\n"

        md += f"""
---

## Description

{description or "No description available."}
"""

        if evidence:
            md += f"""
## Evidence / Proof of Concept

```
{evidence}
```
"""

        if remediation:
            md += f"""
## Remediation

{remediation}
"""

        # Include any extra fields as raw data
        standard_keys = {
            "id",
            "finding_id",
            "domain",
            "target_name",
            "target_domain",
            "severity",
            "title",
            "name",
            "description",
            "details",
            "evidence",
            "proof",
            "remediation",
            "fix",
            "url",
            "endpoint",
            "cvss_score",
            "cvss",
            "cve",
            "cve_id",
            "h1_likely_outcome",
            "verdict",
            "confidence",
            "scan_id",
            "ts",
        }
        extras = {k: v for k, v in finding_data.items() if k not in standard_keys}
        if extras:
            md += """
## Additional Details

```json
"""
            md += json.dumps(extras, indent=2, ensure_ascii=False)
            md += """
```
"""

        # Save
        safe_domain = domain.replace("/", "_").replace(":", "_")
        report_dir = _REPORTS_ROOT / safe_domain
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"{finding_id}.md"

        report_path.write_text(md, encoding="utf-8")
        logger.info("Generated report: %s", report_path)

        # Update summary
        self._update_summary(finding_id, domain, severity, title, str(report_path), now)

        return str(report_path)

    def get_pending_reports(self) -> list[dict[str, Any]]:
        """Return list of report summaries that have been generated."""
        if not _REPORTS_SUMMARY.exists():
            return []
        try:
            data = json.loads(_REPORTS_SUMMARY.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to read reports summary")
        return []

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _update_summary(
        self,
        finding_id: str,
        domain: str,
        severity: str,
        title: str,
        report_path: str,
        when: datetime,
    ) -> None:
        """Append a report entry to ~/.prometheus/comms/global/reports.json."""
        with self._lock:
            try:
                if _REPORTS_SUMMARY.exists():
                    reports = json.loads(_REPORTS_SUMMARY.read_text(encoding="utf-8"))
                else:
                    reports = []
            except (json.JSONDecodeError, OSError):
                logger.debug(
                    "_update_summary: could not read reports summary; starting fresh", exc_info=True
                )
                reports = []

            reports.append(
                {
                    "finding_id": finding_id,
                    "domain": domain,
                    "severity": severity,
                    "title": title,
                    "report_path": report_path,
                    "generated_at": when.isoformat(),
                }
            )

            try:
                _REPORTS_SUMMARY.write_text(
                    json.dumps(reports, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError:
                logger.exception("Failed to write reports summary")


def get_auto_reporter() -> AutoReporter:
    """Convenience accessor for the singleton."""
    return AutoReporter()
