"""JSONL result store + report.md writer for the XBOW harness.

Layout under ``~/.prometheus/eval/xbow/<run_id>/``:

  results.jsonl  — one row per challenge, append-only, atomic.
  report.md      — human-readable render of the same rows.

Row shape mirrors the existing :class:`prometheus.eval.EvalResult`
so the two harnesses can be cross-fed.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

DEFAULT_ROOT = Path.home() / ".prometheus" / "eval" / "xbow"


@dataclass
class XBOWResult:
    """A single challenge's outcome."""

    challenge_id: str
    level: int
    tags: list[str]
    passed: bool
    duration_s: float
    host_port: int
    container_id: str = ""
    run_id: str = ""
    llm_tokens: int = 0
    vuln_count: int = 0
    notes: str = ""
    snippet: str = ""
    match_path: str = ""
    container_flag_visible: str = ""
    error: str = ""
    started_at: str = ""
    finished_at: str = ""
    target: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_run_id() -> str:
    """Return a fresh run id like ``20260615T210300-r3a7b9c1``."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    suffix = f"{os.urandom(4).hex()}"
    return f"{stamp}-{suffix}"


def run_dir(run_id: str, root: Path | None = None) -> Path:
    """Return the per-run directory, creating it on demand."""
    base = root or DEFAULT_ROOT
    d = base / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_row(result: XBOWResult, path: Path) -> None:
    """Append one row to ``results.jsonl`` atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result.to_dict(), sort_keys=True) + "\n")


def write_report(results: Iterable[XBOWResult], dest: Path, *, run_id: str) -> Path:
    """Render a Markdown report from the rows.

    The report mirrors the *shape* of the planted ``benchmarks/README.md``
    table that we just removed — but every row is real.
    """
    rows = list(results)
    total = len(rows)
    passed = sum(1 for r in rows if r.passed)
    total_s = sum(r.duration_s for r in rows)
    mean_s = (total_s / total) if total else 0.0
    total_tokens = sum(r.llm_tokens for r in rows)

    lines: list[str] = []
    lines.append(f"# XBOW run `{run_id}`")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(UTC).isoformat()}")
    lines.append(f"- Challenges: {total}")
    lines.append(f"- Solved: **{passed}/{total}** ({_pct(passed, total)})")
    lines.append(f"- Mean duration: {_fmt_duration(mean_s)}")
    lines.append(f"- Total duration: {_fmt_duration(total_s)}")
    if total_tokens:
        lines.append(f"- LLM tokens (sum): {total_tokens:,}")
    lines.append("")
    lines.append("## Per-challenge")
    lines.append("")
    lines.append("| Challenge | Level | Tags | Pass | Duration | Vulns | Tokens | Notes |")
    lines.append("|-----------|-------|------|------|----------|-------|--------|-------|")
    for r in rows:
        verdict = "✅" if r.passed else "❌"
        notes = r.error or r.notes or ""
        if len(notes) > 80:
            notes = notes[:77] + "..."
        lines.append(
            f"| `{r.challenge_id}` | L{r.level} | {','.join(r.tags)} | {verdict} | "
            f"{_fmt_duration(r.duration_s)} | {r.vuln_count} | {r.llm_tokens:,} | {notes} |"
        )
    lines.append("")
    if any(r.passed and r.snippet for r in rows):
        lines.append("## Solved (flag snippet)")
        lines.append("")
        for r in rows:
            if r.passed and r.snippet:
                lines.append(f"### `{r.challenge_id}`")
                lines.append(f"- Source: `{r.match_path}`")
                lines.append("```text")
                lines.append(r.snippet)
                lines.append("```")
                lines.append("")
    if any(not r.passed for r in rows):
        lines.append("## Unsolved (last signals)")
        lines.append("")
        for r in rows:
            if r.passed:
                continue
            lines.append(f"### `{r.challenge_id}`")
            lines.append(f"- Duration: {_fmt_duration(r.duration_s)}")
            if r.notes:
                lines.append(f"- Last note: {r.notes}")
            if r.error:
                lines.append(f"- Error: {r.error}")
            lines.append("")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, dest)
    return dest


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _pct(n: int, d: int) -> str:
    if not d:
        return "n/a"
    return f"{(n / d) * 100:.1f}%"


def _fmt_duration(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{int(m)}m{int(s):02d}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h{int(m):02d}m"


def _last_vuln_titles(r: XBOWResult) -> list[str]:
    """Best-effort: parse the ``notes`` field if it has a list."""
    return []


__all__ = [
    "DEFAULT_ROOT",
    "XBOWResult",
    "make_run_id",
    "run_dir",
    "append_row",
    "write_report",
]
