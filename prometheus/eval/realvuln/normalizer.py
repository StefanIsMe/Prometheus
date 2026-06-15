"""Normalize prometheus findings to the Semgrep-shaped contract.

RealVuln's :class:`SemgrepParser` reads:

.. code-block:: json

    {
      "version": "1.0.0",
      "results": [
        {
          "check_id": "...",
          "path": "app/views.py",
          "start": {"line": 42, "col": 1},
          "end":   {"line": 42, "col": 1},
          "extra": {
            "message": "...",
            "severity": "ERROR" | "WARNING" | "INFO",
            "metadata": {
              "cwe": ["CWE-89"],
              "confidence": "HIGH" | "MEDIUM" | "LOW",
              "category": "security"
            }
          }
        }
      ]
    }

Matching is (path exact) AND (cwe in gt.acceptable_cwes) AND
(start_line within ±10 of gt.location.start_line..end_line).

Prometheus's on-disk shape is verified from
``/home/stefan/prometheus_runs/api-openai-com_bfd9/vulnerabilities.json``
(1 finding, 18 keys, ``cwe`` is a single string, ``code_locations``
is a list of dicts each with ``file``/``start_line``/``end_line``).
"""

from __future__ import annotations

import re
from typing import Any

# Schema-required severity enum (uppercase).
_SEVERITY_MAP: dict[str, str] = {
    "critical": "ERROR",
    "high": "ERROR",
    "medium": "WARNING",
    "low": "INFO",
    "info": "INFO",
}

# Trust the agent's stated CWE; only do a minimum cleanup.
_CWE_RE = re.compile(r"CWE-\d+")


def _clean_cwe(raw: Any) -> str | None:
    """Extract a ``CWE-NN`` string from whatever the agent emitted."""
    if not isinstance(raw, str):
        return None
    m = _CWE_RE.search(raw)
    return m.group(0) if m else None


def _normalise_path(path: str) -> str:
    """Mirror RealVuln's ``normalise_path`` (backslashes, leading strips)."""
    if not path:
        return ""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _location_to_result(
    loc: dict[str, Any],
    *,
    title: str,
    cwe: str,
    severity: str,
    check_id: str,
) -> dict[str, Any] | None:
    """One ``code_location`` -> one Semgrep result, or None to skip."""
    file = _normalise_path(str(loc.get("file", "")))
    if not file:
        return None
    start_line = loc.get("start_line")
    end_line = loc.get("end_line")
    if not isinstance(start_line, int) or start_line < 1:
        return None
    if not isinstance(end_line, int) or end_line < start_line:
        end_line = start_line

    return {
        "check_id": check_id,
        "path": file,
        "start": {"line": start_line, "col": 1},
        "end": {"line": end_line, "col": 1},
        "extra": {
            "message": title,
            "severity": severity,
            "metadata": {
                "cwe": [cwe],
                "confidence": "HIGH",
                "category": "security",
            },
        },
    }


def prometheus_to_semgrep(
    vuln: dict[str, Any],
    *,
    scanner_slug: str,
) -> list[dict[str, Any]]:
    """Convert one prometheus finding into 0..N Semgrep results.

    Findings with no parseable ``code_locations`` are dropped (the
    Semgrep parser skips empty paths anyway, but failing fast here
    keeps the output file honest).

    A finding with N ``code_locations`` becomes N Semgrep results
    that share the same CWE, severity, and title — the only field
    that varies is ``path`` + ``start``/``end``.
    """
    cwe = _clean_cwe(vuln.get("cwe"))
    if not cwe:
        return []

    raw_sev = str(vuln.get("severity", "info")).lower().strip()
    severity = _SEVERITY_MAP.get(raw_sev, "INFO")
    title = str(vuln.get("title", "")).strip() or cwe
    check_id = f"prometheus.{scanner_slug}"

    locations = vuln.get("code_locations") or []
    if not isinstance(locations, list):
        return []

    out: list[dict[str, Any]] = []
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        result = _location_to_result(
            loc,
            title=title,
            cwe=cwe,
            severity=severity,
            check_id=check_id,
        )
        if result is not None:
            out.append(result)
    return out


def build_results_doc(
    findings: list[dict[str, Any]],
    *,
    scanner_slug: str,
) -> dict[str, Any]:
    """Normalize a list of prometheus findings into the top-level doc.

    This is the function the runner calls per-repo. It wraps the
    flat results list in the ``{"version": "1.0.0", "results": [...]}``
    envelope the scorer requires.
    """
    flat: list[dict[str, Any]] = []
    for v in findings:
        flat.extend(prometheus_to_semgrep(v, scanner_slug=scanner_slug))
    return {"version": "1.0.0", "results": flat}
