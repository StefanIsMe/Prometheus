"""XBOW challenge loader — clone, build, start, stop.

The XBOW validation-benchmarks repo is a curated Jeopardy-style CTF
corpus of self-contained docker-compose challenges. Each challenge:

  1. Lives at ``benchmarks/<CHALLENGE_ID>/`` in the upstream repo.
  2. Has a ``Makefile`` + ``docker-compose.yml``.
  3. Accepts a ``FLAG`` make-variable (forwarded to
     ``docker compose build`` as a build-arg) so the flag can be
     injected at build time and never appears in any HTTP response.
  4. Exposes a single port (typically 80 or 3000) once ``make run``
     (or ``docker compose up -d --wait``) is invoked.

This module handles the four steps for one challenge:

  * :func:`fetch_challenge` — ensure the upstream clone exists.
  * :func:`generate_unique_flag` — produce ``FLAG{<id>-<uuid4>}``
    so two harness runs never collide even on the same challenge.
  * :func:`build_challenge` — run ``make build FLAG=$flag``.
  * :func:`start_challenge` — ``docker compose up -d --wait`` and
    return the container id.
  * :func:`stop_challenge` — ``docker stop && docker rm`` wrapped in
    ``try/finally`` so a prometheus crash cannot leak containers.
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

XBOW_REPO_URL = "https://github.com/xbow-engineering/validation-benchmarks.git"


# ----------------------------------------------------------------------
# Repo fetching
# ----------------------------------------------------------------------
def fetch_challenge(
    challenge_id: str,
    dest_root: Path,
    *,
    force_clone: bool = False,
) -> Path:
    """Ensure the XBOW repo is cloned and return the challenge dir.

    Args:
        challenge_id: e.g. ``"XBEN-001-24"``. Must match a folder
            name under ``benchmarks/`` in the upstream repo.
        dest_root: a writable directory. The shallow clone is placed
            at ``dest_root/xbow/``; the returned challenge path is
            ``dest_root/xbow/benchmarks/<challenge_id>``.
        force_clone: if True, delete and re-clone the repo even if
            ``dest_root/xbow`` already exists. Default False; we
            only clone when the directory is missing.

    Returns:
        The path to the challenge directory.
    """
    repo_dir = dest_root / "xbow"
    challenge_dir = repo_dir / "benchmarks" / challenge_id

    if not (repo_dir / ".git").is_dir() or force_clone:
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        if force_clone and repo_dir.exists():
            subprocess.run(["rm", "-rf", str(repo_dir)], check=True)
        logger.info("Cloning XBOW validation-benchmarks into %s", repo_dir)
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                XBOW_REPO_URL,
                str(repo_dir),
            ],
            check=True,
        )
    else:
        # Cheap fetch so newly-published challenges become visible
        # without a full re-clone. Tolerate failure (offline, etc.).
        try:
            subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            logger.debug("XBOW fetch failed (continuing with cached clone): %s", exc)

    if not challenge_dir.is_dir():
        available = sorted(
            p.name
            for p in (repo_dir / "benchmarks").iterdir()
            if p.is_dir() and p.name.startswith("XBEN-")
        )
        raise FileNotFoundError(
            f"XBOW challenge {challenge_id!r} not found at {challenge_dir}. "
            f"Available: {', '.join(available) or '(none)'}."
        )

    # Sanity-check the layout: docker-compose.yml + Makefile + app/.
    for required in ("docker-compose.yml", "Makefile"):
        if not (challenge_dir / required).is_file():
            raise RuntimeError(
                f"XBOW challenge {challenge_id!r} at {challenge_dir} is missing "
                f"the required file {required!r}. Refusing to build."
            )

    return challenge_dir


# ----------------------------------------------------------------------
# Flag generation
# ----------------------------------------------------------------------
def generate_unique_flag(challenge_id: str) -> str:
    """Return a fresh ``FLAG{<id>-<uuid4>}`` string for this run.

    The uuid4 suffix is what keeps two runs from ever sharing a flag
    (and therefore from spuriously "solving" because a stale container
    from a previous run still had the old flag in ``/proc/1/environ``).
    """
    return f"FLAG{{{challenge_id}-{uuid.uuid4().hex}}}"


# ----------------------------------------------------------------------
# Build / start / stop
# ----------------------------------------------------------------------
def _run(cmd: list[str], cwd: Path, *, timeout: int = 900) -> subprocess.CompletedProcess:
    """Thin wrapper around subprocess.run with logging + a hard cap."""
    logger.info("$ cd %s && %s", cwd, " ".join(shlex.quote(c) for c in cmd))
    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed = time.monotonic() - start
    if proc.returncode != 0:
        logger.error(
            "Command failed after %.1fs: %s\nstdout: %s\nstderr: %s",
            elapsed,
            " ".join(shlex.quote(c) for c in cmd),
            proc.stdout[-2000:],
            proc.stderr[-2000:],
        )
    else:
        logger.info("Command ok after %.1fs", elapsed)
    return proc


def build_challenge(challenge_dir: Path, flag: str, *, timeout: int = 900) -> None:
    """Run ``make build FLAG=$flag`` in the challenge dir.

    XBEN's ``common.mk`` (included by every challenge's Makefile)
    forwards ``FLAG`` to ``docker compose build`` as a build-arg, and
    uses ``openssl sha256 $CHALLENGE`` as a default when the var is
    unset. We always pass it explicitly so the flag is unique to
    this harness run.
    """
    proc = _run(["make", "build", f"FLAG={flag}"], challenge_dir, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"make build failed for {challenge_dir.name} (rc={proc.returncode}). "
            f"stderr tail: {proc.stderr[-500:]!r}"
        )


def start_challenge(challenge_dir: Path, *, timeout: int = 600) -> str:
    """Bring the challenge up and return the primary container id.

    ``docker compose up -d --wait`` blocks until every service's
    healthcheck passes, which is what XBEN's ``Makefile run:`` target
    does. We use the underlying compose command directly so the
    harness can read the container id and tear it down deterministically
    later (compose's own ``down`` would also work, but it nukes
    anonymous volumes we don't own).
    """
    proc = _run(
        ["docker", "compose", "up", "-d", "--wait"],
        challenge_dir,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker compose up failed for {challenge_dir.name} (rc={proc.returncode}). "
            f"stderr tail: {proc.stderr[-500:]!r}"
        )

    # The compose project name defaults to the directory basename, so
    # two builds in different clones don't collide. The container id
    # of the first service is enough — we just need *something* to
    # `docker stop` later.
    list_proc = _run(
        [
            "docker",
            "compose",
            "ps",
            "-q",
            "--status",
            "running",
        ],
        challenge_dir,
        timeout=30,
    )
    container_id = list_proc.stdout.strip().splitlines()[0] if list_proc.stdout.strip() else ""
    if not container_id:
        raise RuntimeError(
            f"docker compose up reported success but no running container was found "
            f"for {challenge_dir.name}. Compose output: {list_proc.stdout!r}"
        )
    logger.info("Challenge %s is up as container %s", challenge_dir.name, container_id[:12])
    return container_id


def discover_host_port(challenge_dir: Path, internal_port: int = 80) -> int:
    """Return the host port the running challenge's primary service is on.

    XBOW's ``docker-compose.yml`` mixes two styles:

    * ``ports: - 80`` — no host binding; docker assigns a random
      ephemeral port.
    * ``ports: - "5000:5000"`` — explicit host port.

    We use ``docker compose port <svc> <internal>`` which works for
    both cases (it reads the actual host port docker mapped). The
    harness then talks to ``127.0.0.1:<host_port>``.

    The ``<svc>`` name is heuristic: the first non-``db`` / non-``mysql``
    service defined in the compose file. That matches the convention
    every XBOW challenge follows (the actual web app service is the
    one with the healthcheck on the listen port).
    """
    import json
    import re

    compose_path = challenge_dir / "docker-compose.yml"
    text = compose_path.read_text(encoding="utf-8", errors="replace")
    # Strip YAML comments then look for top-level `services:` children
    cleaned = re.sub(r"#[^\n]*", "", text)
    # First service name after `services:` — naive but good enough for
    # XBOW (no `&` anchors, no `---` multi-doc, every challenge has a
    # single document).
    m = re.search(r"^services:\s*\n((?:\s{2}\S.*\n?)+)", cleaned, re.MULTILINE)
    if not m:
        raise RuntimeError(
            f"Could not parse services block in {compose_path}; refusing to discover port."
        )
    service_names: list[str] = []
    for ln in m.group(1).splitlines():
        s = ln.strip()
        if s and not s.startswith("-") and ":" in s:
            name = s.split(":", 1)[0].strip()
            if name and name not in service_names:
                service_names.append(name)
    candidates = [s for s in service_names if s.lower() not in ("db", "mysql", "postgres", "mariadb")]
    if not candidates:
        candidates = service_names
    if not candidates:
        raise RuntimeError(f"No service names found in {compose_path}")
    primary = candidates[0]

    proc = _run(
        ["docker", "compose", "port", primary, str(internal_port)],
        challenge_dir,
        timeout=15,
    )
    out = proc.stdout.strip()
    if not out or ":" not in out:
        raise RuntimeError(
            f"docker compose port {primary} {internal_port} returned {out!r}; "
            f"compose stderr tail: {proc.stderr[-300:]!r}"
        )
    host_port = int(out.rsplit(":", 1)[1])
    logger.info("Challenge %s primary service %s is on host port %s", challenge_dir.name, primary, host_port)
    return host_port


def stop_challenge(challenge_dir: Path, container_id: str, *, timeout: int = 60) -> None:
    """Tear the challenge down.

    Always runs in a ``try/finally`` at the caller so a prometheus
    crash cannot leave the container running. We ``docker stop``
    first (so healthcheck-failing apps still get a chance to flush),
    then ``docker compose down -v`` to remove the project + the
    anonymous volumes the build created.
    """
    try:
        if container_id:
            try:
                _run(
                    ["docker", "stop", "--time", "10", container_id],
                    cwd=Path.cwd(),
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                logger.warning("docker stop timed out for %s; forcing kill", container_id[:12])
                subprocess.run(
                    ["docker", "kill", container_id],
                    check=False,
                    capture_output=True,
                )
    finally:
        try:
            _run(
                ["docker", "compose", "down", "-v", "--remove-orphans"],
                challenge_dir,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("docker compose down timed out for %s", challenge_dir.name)
