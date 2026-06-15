"""RealVuln-Benchmark target list + ground-truth access.

The benchmark ships 26 Python repos. Each repo has a
``ground-truth/<slug>/ground-truth.json`` carrying the pinned
``repo_url`` + ``commit_sha`` and a list of labelled findings (real
vulns + ``is_vulnerable: false`` traps).

This module is the only place that knows the slugs and the layout
on disk. The runner talks to it via :func:`iter_repos`.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


# RealVuln-Beta: 26 Python repos. Slugs match ground-truth/ subdirs.
# Adding a 27th? Append it here and the harness will pick it up.
REPO_SLUGS: list[str] = [
    "realvuln-damn-vulnerable-flask-application",
    "realvuln-damn-vulnerable-graphql-application",
    "realvuln-djangoat",
    "realvuln-dsvpwa",
    "realvuln-dsvw",
    "realvuln-dvblab",
    "realvuln-dvpwa",
    "realvuln-extremely-vulnerable-flask-app",
    "realvuln-flask-xss",
    "realvuln-insecure-web",
    "realvuln-intentionally-vulnerable-python-application",
    "realvuln-lets-be-bad-guys",
    "realvuln-owasp-web-playground",
    "realvuln-pygoat",
    "realvuln-python-app",
    "realvuln-python-insecure-app",
    "realvuln-pythonssti",
    "realvuln-threatbyte",
    "realvuln-vampi",
    "realvuln-vfapi",
    "realvuln-vulnerable-api",
    "realvuln-vulnerable-flask-app",
    "realvuln-vulnerable-python-apps",
    "realvuln-vulnerable-tornado-app",
    "realvuln-vulnpy",
    "realvuln-vulpy",
]


BENCHMARK_REPO_URL = "https://github.com/kolega-ai/Real-Vuln-Benchmark.git"
BENCHMARK_REPO_DIR = Path.home() / ".prometheus" / "benchmarks" / "Real-Vuln-Benchmark"
GROUND_TRUTH_DIR = BENCHMARK_REPO_DIR / "ground-truth"
SCAN_RESULTS_DIR = BENCHMARK_REPO_DIR / "scan-results"

TARGET_REPO_ROOT = Path.home() / ".prometheus" / "realvuln_repos"

# Stable scanner slug — the scorer consumes scan-results/{repo}/{slug}/*.
SCANNER_SLUG = "prometheus-v1"


@dataclass(frozen=True)
class RepoMeta:
    """Metadata for one target repo, loaded from ground-truth.json."""

    slug: str
    repo_url: str
    commit_sha: str
    framework: str
    language: str
    loc: int
    total_vulns: int
    total_traps: int

    @property
    def total_findings(self) -> int:
        return self.total_vulns + self.total_traps


def fetch_ground_truth(*, force: bool = False, timeout: int = 300) -> Path:
    """Shallow-clone the benchmark repo (or refresh).

    The benchmark repo is small (just ``ground-truth/``,
    ``scan-results/``, ``scorer/``). A shallow clone at HEAD is
    fine; the ground truth is a snapshot, not a stream.

    Args:
        force: if True, delete and re-clone even if the dir exists.
        timeout: seconds to wait for ``git clone``.

    Returns:
        The path to :data:`BENCHMARK_REPO_DIR`.
    """
    if force and BENCHMARK_REPO_DIR.exists():
        logger.info("Forcing re-clone of benchmark repo at %s", BENCHMARK_REPO_DIR)
        shutil.rmtree(BENCHMARK_REPO_DIR)
    if BENCHMARK_REPO_DIR.is_dir() and (BENCHMARK_REPO_DIR / ".git").is_dir():
        # Cheap fetch — tolerates offline (the existing clone is the
        # source of truth if upstream is unreachable).
        try:
            subprocess.run(
                ["git", "-C", str(BENCHMARK_REPO_DIR), "fetch", "--depth", "1", "origin"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
            return BENCHMARK_REPO_DIR
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.debug("Fetch failed (%s); using cached clone", exc)
            return BENCHMARK_REPO_DIR

    BENCHMARK_REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Cloning RealVuln-Benchmark into %s", BENCHMARK_REPO_DIR)
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            BENCHMARK_REPO_URL,
            str(BENCHMARK_REPO_DIR),
        ],
        check=True,
        timeout=timeout,
    )
    return BENCHMARK_REPO_DIR


def _load_ground_truth(slug: str) -> RepoMeta:
    """Read ``ground-truth/<slug>/ground-truth.json`` and return meta."""
    gt_path = GROUND_TRUTH_DIR / slug / "ground-truth.json"
    if not gt_path.is_file():
        raise FileNotFoundError(
            f"Ground truth missing for {slug!r} at {gt_path}. "
            f"Did `fetch_ground_truth` run? Available: "
            f"{', '.join(sorted(p.name for p in GROUND_TRUTH_DIR.iterdir() if p.is_dir())) or '(none)'}"
        )
    raw = json.loads(gt_path.read_text(encoding="utf-8"))

    findings = raw.get("findings", []) or []
    vulns = sum(1 for f in findings if f.get("is_vulnerable", True))
    traps = sum(1 for f in findings if not f.get("is_vulnerable", True))

    return RepoMeta(
        slug=slug,
        repo_url=raw.get("repo_url", ""),
        commit_sha=raw.get("commit_sha", ""),
        framework=raw.get("framework", ""),
        language=raw.get("language", "python"),
        loc=int(raw.get("loc", 0) or 0),
        total_vulns=vulns,
        total_traps=traps,
    )


def iter_repos(slugs: list[str] | None = None) -> Iterator[RepoMeta]:
    """Yield :class:`RepoMeta` for each requested slug (default: all 26)."""
    fetch_ground_truth()
    targets = slugs or REPO_SLUGS
    for slug in targets:
        try:
            yield _load_ground_truth(slug)
        except FileNotFoundError as exc:
            logger.warning("Skipping %s: %s", slug, exc)
