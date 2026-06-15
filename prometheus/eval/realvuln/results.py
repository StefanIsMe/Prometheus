"""JSONL row store + report.md writer for the RealVuln harness.

Layout under ``~/.prometheus/eval/realvuln/<run_id>/``:

  results.jsonl                  — one row per repo, append-only, atomic.
  report.md                      — Markdown render of the same rows.
  <repo>.scorecard.json          — raw `score.py` JSON per repo (if --runs scoring ran).
  scan-results/<repo>/<slug>/    — symlink-or-mirror of what we wrote to the benchmark repo.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

DEFAULT_ROOT = Path.home() / ".prometheus" / "eval" / "realvuln"


@dataclass
class RealVulnResult:
    """One repo's outcome for one run."""

    repo_slug: str
    total_vulns: int
    total_traps: int
    prom_vuln_count: int
    prom_ran: bool
    duration_s: float
    # Filled by score.py after the run.
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    f2: float = 0.0
    fpr: float = 0.0
    run_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    notes: str = ""

    @property
    def total_findings(self) -> int:
        return self.total_vulns + self.total_traps

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_run_id() -> str:
    """Return a fresh run id like ``20260615T210300-r3a7b9c1``."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    suffix = os.urandom(4).hex()
    return f"{stamp}-{suffix}"


def run_dir(run_id: str, root: Path | None = None) -> Path:
    """Return the per-run directory, creating it on demand."""
    base = root or DEFAULT_ROOT
    d = base / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_row(result: RealVulnResult, path: Path) -> None:
    """Append one row to ``results.jsonl`` atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result.to_dict(), sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[RealVulnResult]:
    rows: list[RealVulnResult] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping corrupt row: %s", exc)
            continue
        try:
            rows.append(RealVulnResult(**d))
        except TypeError as exc:
            logger.warning("Skipping malformed row: %s", exc)
    return rows


def write_report(
    results: Iterable[RealVulnResult],
    dest: Path,
    *,
    run_id: str,
) -> Path:
    """Render a Markdown report from the rows. Sorted by F2 desc, then recall."""
    rows = list(results)
    rows.sort(key=lambda r: (-r.f2, -r.recall, r.repo_slug))

    lines: list[str] = []
    lines.append(f"# RealVuln-Benchmark run `{run_id}`")
    lines.append("")
    lines.append(f"_Generated {datetime.now(UTC).isoformat(timespec='seconds')}_")
    lines.append("")

    if not rows:
        lines.append("No results in this run.")
        return dest.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Summary.
    scored = [r for r in rows if r.prom_ran and not r.error]
    if scored:
        avg_f2 = sum(r.f2 for r in scored) / len(scored)
        avg_p = sum(r.precision for r in scored) / len(scored)
        avg_r = sum(r.recall for r in scored) / len(scored)
        total_tp = sum(r.tp for r in scored)
        total_fp = sum(r.fp for r in scored)
        total_fn = sum(r.fn for r in scored)
        total_tn = sum(r.tn for r in scored)
        total_vulns = sum(r.total_vulns for r in scored)
        total_traps = sum(r.total_traps for r in scored)
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Repos scored: **{len(scored)}** / {len(rows)}")
        lines.append(
            f"- Total vulns in ground truth: **{total_vulns}** (across {len(scored)} repos)"
        )
        lines.append(f"- Total FP traps in ground truth: **{total_traps}**")
        lines.append(
            f"- Aggregate TP/FP/FN/TN: **{total_tp}** / **{total_fp}** / **{total_fn}** / **{total_tn}**"
        )
        lines.append(f"- Mean F2: **{avg_f2:.3f}**")
        lines.append(f"- Mean precision: **{avg_p:.3f}**")
        lines.append(f"- Mean recall: **{avg_r:.3f}**")
        lines.append("")

    # Per-repo table.
    lines.append("## Per-repo scorecard")
    lines.append("")
    lines.append(
        "| repo | vulns | traps | prom ran | TP | FP | FN | TN | precision | recall | F2 | duration | error |"
    )
    lines.append("|---|---:|---:|:---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for r in rows:
        ran = "✅" if r.prom_ran else "❌"
        err = (r.error or "").replace("|", "\\|")[:80]
        lines.append(
            f"| `{r.repo_slug}` | {r.total_vulns} | {r.total_traps} | {ran} | "
            f"{r.tp} | {r.fp} | {r.fn} | {r.tn} | "
            f"{r.precision:.3f} | {r.recall:.3f} | {r.f2:.3f} | "
            f"{r.duration_s:.1f}s | {err} |"
        )
    lines.append("")
    lines.append(
        "Sort: F2 desc, then recall desc. "
        "Prom ran = the prometheus subprocess completed and produced a parseable `vulnerabilities.json`."
    )
    lines.append("")

    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def report_from_jsonl(jsonl: Path, dest: Path, *, run_id: str) -> Path:
    """Read a ``results.jsonl`` and render ``report.md`` next to it."""
    rows = _read_jsonl(jsonl)
    return write_report(rows, dest, run_id=run_id)
