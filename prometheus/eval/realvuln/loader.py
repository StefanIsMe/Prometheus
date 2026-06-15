"""Target-repo fetch + pin-verify.

Each target repo is a small Python project (a few hundred lines on
average, 78 findings max for ``realvuln-vulnpy``). We shallow-clone
to ``~/.prometheus/realvuln_repos/<slug>/`` and ``git checkout`` the
pinned SHA. No Docker, no service to start — the targets are static
source code, and the prometheus sandbox can read them directly.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .challenges import TARGET_REPO_ROOT

logger = logging.getLogger(__name__)

# Per-step timeouts (seconds). Match realvuln's clone_repos.py.
_CLONE_TIMEOUT = 300
_FETCH_TIMEOUT = 60
_CHECKOUT_TIMEOUT = 30


def fetch_target_repo(
    slug: str,
    repo_url: str,
    commit_sha: str,
    *,
    force: bool = False,
) -> Path:
    """Ensure the target repo is cloned and pinned to ``commit_sha``.

    Idempotent: if the repo already exists and the working tree is
    at ``commit_sha``, do nothing. If the dir is missing, clone. If
    the dir exists but HEAD is wrong, fetch + checkout.

    Args:
        slug: the RealVuln slug (e.g. ``realvuln-pythonssti``).
        repo_url: the upstream URL from ground-truth.json.
        commit_sha: the pinned commit from ground-truth.json.
        force: delete and re-clone even if the dir exists.

    Returns:
        The path to the cloned repo root.
    """
    target_dir = TARGET_REPO_ROOT / slug

    if force and target_dir.exists():
        logger.info("Forcing re-clone of %s", slug)
        import shutil

        shutil.rmtree(target_dir)

    if not (target_dir / ".git").is_dir():
        TARGET_REPO_ROOT.mkdir(parents=True, exist_ok=True)
        logger.info("Cloning %s -> %s @ %s", repo_url, target_dir, commit_sha[:8])
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
            check=True,
            timeout=_CLONE_TIMEOUT,
        )

    # Cheap fetch so the pinned SHA is reachable (depth-1 clones may
    # not have it on the initial shallow tip).
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(target_dir),
                "fetch",
                "--depth",
                "1",
                "origin",
                commit_sha,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_FETCH_TIMEOUT,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("Fetch of %s failed (continuing): %s", commit_sha[:8], exc)

    # Checkout. If HEAD is already on commit_sha, this is a no-op.
    if not verify_pinned(target_dir, commit_sha):
        logger.info("Checking out %s @ %s", slug, commit_sha[:8])
        subprocess.run(
            ["git", "-C", str(target_dir), "checkout", commit_sha],
            check=True,
            timeout=_CHECKOUT_TIMEOUT,
        )

    if not verify_pinned(target_dir, commit_sha):
        raise RuntimeError(
            f"Failed to pin {slug} to {commit_sha} at {target_dir}. "
            f"Try: rm -rf {target_dir} and re-run."
        )

    return target_dir


def verify_pinned(repo_dir: Path, commit_sha: str) -> bool:
    """Return True if ``repo_dir`` is on ``commit_sha`` (cleanly or dirty)."""
    head_proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if head_proc.returncode != 0:
        return False
    return head_proc.stdout.strip() == commit_sha.strip()
