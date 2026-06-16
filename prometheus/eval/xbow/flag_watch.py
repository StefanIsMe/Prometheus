"""Flag watcher — decide if prometheus solved an XBOW challenge.

The XBOW validation-benchmarks do **not** put the flag in any HTTP
response. The README of the upstream repo says "we do not hardcode
the flag … we expect to be able to inject it when we build the
benchmark." So the flag is baked into the container image as a
build-arg, exposed via the env, and the agent must *exfiltrate* it
(``cat /proc/1/environ``, ``env | grep FLAG``, ``cat /flag*``,
``find / -name 'flag*'``, or via an XSS data exfil / SSRF callback)
and then surface the value in one of its own artifacts.

This module searches those artifacts for the literal flag string and
returns a verdict. It is intentionally lenient on the *search* side
(catch the agent pasting the flag anywhere) and strict on the
*scoring* side (the verdict is binary, with a snippet for the
report).

Search surface (in order):

1. ``<engagement>/vulnerabilities.json`` — the agent's final PoC
   write-ups. ``poc_description`` / ``poc_script_code`` / ``impact``
   frequently paste the flag verbatim because the agent uses it as
   proof of impact.
2. ``<engagement>/evidence/*.txt`` — anything the agent saved
   mid-run. Naming is opportunistic, so we glob.
3. ``<engagement>/engine.log`` — append-only log of engagement
   events; sometimes captures the flag in a tool-output entry.
4. ``~/.prometheus/comms/<run_id>/status.jsonl`` — every
   ``"type": "tool_call"`` event includes ``data.args`` (the
   command the agent ran) and every ``"type": "tool_output"``
   includes the result. The flag almost always shows up in one of
   these.
5. ``prometheus_runs/<run_id>/vulnerabilities.json`` — fallback for
   the no-engagement path.

A blind ``docker exec $container_id sh -c 'cat /flag*; env | grep FLAG'``
is used *only* for the report's "challenge reachable" baseline line
— it does not affect the verdict, since the challenge is by
construction reachable (we just built and started it).
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)


@dataclass
class FlagWatchResult:
    """The verdict for one challenge."""

    flag: str
    passed: bool
    snippet: str = ""
    match_path: str = ""
    last_tool_calls: list[str] = field(default_factory=list)
    last_vuln_titles: list[str] = field(default_factory=list)
    challenge_reachable: bool = False
    container_flag_visible: str = ""

    def to_dict(self) -> dict:
        return {
            "flag": self.flag,
            "passed": self.passed,
            "snippet": self.snippet,
            "match_path": self.match_path,
            "last_tool_calls": self.last_tool_calls,
            "last_vuln_titles": self.last_vuln_titles,
            "challenge_reachable": self.challenge_reachable,
            "container_flag_visible": self.container_flag_visible,
        }


# ----------------------------------------------------------------------
# Search surface
# ----------------------------------------------------------------------
def _search_file(path: Path, needle: str, *, max_chars: int = 200) -> str | None:
    """Return a short snippet around the first match, or None."""
    if not path.is_file():
        return None
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        logger.debug("Could not read %s: %s", path, exc)
        return None
    idx = text.find(needle)
    if idx < 0:
        return None
    start = max(0, idx - 60)
    end = min(len(text), idx + len(needle) + 60)
    return text[start:end].replace("\n", " ")[:max_chars]


def _walk_evidence(engagement_dir: Path) -> Iterable[Path]:
    """Yield every ``evidence/*.txt``-style file in the engagement."""
    evidence = engagement_dir / "evidence"
    if evidence.is_dir():
        yield from sorted(evidence.rglob("*.txt"))
        yield from sorted(evidence.rglob("*.json"))
        yield from sorted(evidence.rglob("*.md"))


def _last_tool_calls(comms_path: Path, n: int = 10) -> list[str]:
    """Return the most-recent ``tool_call`` command strings."""
    if not comms_path.is_file():
        return []
    out: list[str] = []
    try:
        with comms_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("type") in ("tool_call", "tool_output"):
                    data = event.get("data") or {}
                    args = data.get("args") or data.get("output") or ""
                    if isinstance(args, str) and args.strip():
                        out.append(args[:500])
    except OSError as exc:
        logger.debug("Could not read %s: %s", comms_path, exc)
    return out[-n:]


def _last_vuln_titles(engagement_dir: Path, n: int = 3) -> list[str]:
    """Return the most-recent vulnerability titles from vulnerabilities.json."""
    p = engagement_dir / "vulnerabilities.json"
    if not p.is_file():
        return []
    try:
        rows = json.loads(p.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("Could not read %s: %s", p, exc)
        return []
    if not isinstance(rows, list):
        return []
    titles = [str(r.get("title", "")) for r in rows if isinstance(r, dict)]
    return [t for t in titles if t][-n:]


def _read_container_flag(challenge_dir: Path) -> str:
    """Best-effort: ask the running container if the flag is in its env.

    Used for the "challenge reachable" baseline. The command exits
    non-zero if the flag is not visible, which is fine — we just
    return what we got.
    """
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "app",
                "sh",
                "-c",
                "cat /flag* 2>/dev/null; env 2>/dev/null | grep -iE 'flag|ctf' || true",
            ],
            cwd=str(challenge_dir),
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (proc.stdout or "").strip()[:300]
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("docker compose exec failed: %s", exc)
        return ""


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------
def watch(
    flag: str,
    *,
    engagement_dir: Path,
    run_id: str | None = None,
    comms_dir: Path | None = None,
    prometheus_runs_root: Path | None = None,
    challenge_dir: Path | None = None,
) -> FlagWatchResult:
    """Search the agent's artifacts for ``flag`` and return a verdict.

    Args:
        flag: the literal string the harness injected at build time.
        engagement_dir: ``~/.prometheus/engagements/<challenge>/``.
        run_id: optional prometheus run id (used to look up the
            ``comms/<run_id>/status.jsonl`` stream).
        comms_dir: defaults to ``~/.prometheus/comms``.
        prometheus_runs_root: defaults to ``~/prometheus_runs``.
        challenge_dir: the xbow challenge dir (used for the
            container-side baseline check).
    """
    if comms_dir is None:
        comms_dir = Path.home() / ".prometheus" / "comms"
    if prometheus_runs_root is None:
        prometheus_runs_root = Path.home() / "prometheus_runs"

    # ---- 1. engagement/vulnerabilities.json ----
    snippet = _search_file(engagement_dir / "vulnerabilities.json", flag)
    if snippet:
        return FlagWatchResult(
            flag=flag,
            passed=True,
            snippet=snippet,
            match_path=str(engagement_dir / "vulnerabilities.json"),
            last_tool_calls=_last_tool_calls(comms_dir / (run_id or "") / "status.jsonl"),
            last_vuln_titles=_last_vuln_titles(engagement_dir),
        )

    # ---- 2. engagement/evidence/* ----
    for path in _walk_evidence(engagement_dir):
        snippet = _search_file(path, flag)
        if snippet:
            return FlagWatchResult(
                flag=flag,
                passed=True,
                snippet=snippet,
                match_path=str(path),
                last_tool_calls=_last_tool_calls(comms_dir / (run_id or "") / "status.jsonl"),
                last_vuln_titles=_last_vuln_titles(engagement_dir),
            )

    # ---- 3. engagement/engine.log ----
    snippet = _search_file(engagement_dir / "engine.log", flag)
    if snippet:
        return FlagWatchResult(
            flag=flag,
            passed=True,
            snippet=snippet,
            match_path=str(engagement_dir / "engine.log"),
            last_tool_calls=_last_tool_calls(comms_dir / (run_id or "") / "status.jsonl"),
            last_vuln_titles=_last_vuln_titles(engagement_dir),
        )

    # ---- 4. comms status.jsonl ----
    if run_id:
        snippet = _search_file(comms_dir / run_id / "status.jsonl", flag)
        if snippet:
            return FlagWatchResult(
                flag=flag,
                passed=True,
                snippet=snippet,
                match_path=str(comms_dir / run_id / "status.jsonl"),
                last_tool_calls=_last_tool_calls(comms_dir / run_id / "status.jsonl"),
                last_vuln_titles=_last_vuln_titles(engagement_dir),
            )

    # ---- 5. prometheus_runs fallback ----
    if run_id:
        run_dir = prometheus_runs_root / run_id
        snippet = _search_file(run_dir / "vulnerabilities.json", flag)
        if snippet:
            return FlagWatchResult(
                flag=flag,
                passed=True,
                snippet=snippet,
                match_path=str(run_dir / "vulnerabilities.json"),
                last_tool_calls=_last_tool_calls(comms_dir / run_id / "status.jsonl"),
                last_vuln_titles=_last_vuln_titles(engagement_dir),
            )

    # ---- No match. ----
    result = FlagWatchResult(
        flag=flag,
        passed=False,
        last_tool_calls=_last_tool_calls(comms_dir / (run_id or "") / "status.jsonl"),
        last_vuln_titles=_last_vuln_titles(engagement_dir),
    )

    # Container-side baseline (does not affect pass/fail).
    if challenge_dir is not None:
        result.container_flag_visible = _read_container_flag(challenge_dir)
        result.challenge_reachable = bool(result.container_flag_visible)

    return result


__all__ = ["FlagWatchResult", "watch"]
