"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from prometheus.config import load_settings
from prometheus.runtime.backends import get_backend
from prometheus.runtime.caido_bootstrap import bootstrap_caido


logger = logging.getLogger(__name__)


# In-container Caido sidecar port (matches the image's caido-cli bind).
# Tor SOCKS5 proxy reachable from inside Docker containers via host-gateway.
_TOR_PROXY = "socks5://host.docker.internal:9050"


_CONTAINER_CAIDO_PORT = 48080

# Browser-harness mount point inside the sandbox.
_BROWSER_HARNESS_HOST = Path.home() / "browser-harness"
_BROWSER_HARNESS_MOUNT = "/opt/browser-harness"

# Browsercode mount point inside the sandbox.
_BROWSERCODE_HOST = Path.home() / "browsercode"
_BROWSERCODE_MOUNT = "/opt/browsercode"

# Scan pipeline script mount — the script isn't in the upstream prometheus-sandbox image.
# Mount the entire scripts/ directory so Docker can create /scripts/ as a mount point.
_PIPELINE_SCRIPTS_HOST = Path(
    os.environ.get(
        "PROMETHEUS_SCRIPTS_DIR", str(Path(__file__).resolve().parent.parent / "scripts")
    )
)
_PIPELINE_SCRIPTS_MOUNT = "/scripts"

# Extra bind mounts pending injection into the next Docker container creation.
# Set by create_or_reuse(), consumed by docker_client._create_container().
_pending_extra_bind_mounts: list[  # codeql[py/unused-global-variable] : suppressed via the security dashboard triage
    dict[str, str]
] = []  # codeql[py/unused-global-variable] : read via `global` inside _set_extra_bind_mounts() and imported by docker_client._create_container()


_SESSION_CACHE: dict[str, dict[str, Any]] = {}


async def _setup_browser_automation(session: Any) -> None:
    """Install browser-harness deps and start Chromium with CDP inside the sandbox.

    Called after Caido bootstrap. Non-fatal — if this fails, the scan
    continues without browser tools.
    """
    # Step 1: Install browser-harness Python dependencies.
    # Bypass Tor for pip install — this is internal setup, not scanning traffic.
    logger.info("Installing browser-harness dependencies in sandbox...")
    deps_result = await session.exec(
        "sh",
        "-c",
        "http_proxy= https_proxy= ALL_PROXY= "
        "/app/.venv/bin/pip install --no-cache-dir "
        "cdp-use==1.4.5 fetch-use==0.4.0 pillow websockets 2>&1 | tail -5",
        timeout=120,
    )
    if deps_result.ok():
        deps_out = deps_result.stdout.decode("utf-8", errors="replace").strip()
        logger.info("browser-harness deps installed: %s", deps_out[:200])
    else:
        stderr = deps_result.stderr.decode("utf-8", errors="replace").strip()[:200]
        logger.warning("browser-harness deps install failed: %s", stderr)
        return

    # Step 2: Start Chromium with CDP (remote debugging port).
    # Chromium is already installed in the sandbox image at /usr/bin/chromium.
    logger.info("Starting Chromium with CDP on port 9222...")
    chrome_result = await session.exec(
        "sh",
        "-c",
        "nohup /usr/bin/chromium "
        "--no-sandbox "
        "--disable-gpu "
        "--disable-dev-shm-usage "
        "--headless=new "
        "--remote-debugging-port=9222 "
        "--remote-debugging-address=0.0.0.0 "
        "--remote-allow-origins=* "
        "--no-first-run "
        "--no-default-browser-check "
        "--disable-background-networking "
        "--disable-extensions "
        "--user-data-dir=/tmp/chromium-cdp "
        ">/tmp/chromium-cdp.log 2>&1 & "
        "sleep 2 && curl -s --max-time 5 http://127.0.0.1:9222/json/version | head -5",
        timeout=30,
    )
    if chrome_result.ok():
        chrome_out = chrome_result.stdout.decode("utf-8", errors="replace").strip()
        if "Browser" in chrome_out or "webSocketDebuggerUrl" in chrome_out:
            logger.info("Chromium CDP ready: %s", chrome_out[:200])
        else:
            logger.warning("Chromium CDP may not be ready: %s", chrome_out[:200])
    else:
        stderr = chrome_result.stderr.decode("utf-8", errors="replace").strip()[:200]
        logger.warning("Chromium CDP start failed: %s", stderr)


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, str]],
    allow_direct: bool = False,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry mounts its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container.

    Args:
        allow_direct: If True, tools inside the container may fall back
            to direct connections when Tor is unreachable.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        entries[ws_subdir] = LocalDir(src=Path(host_path).expanduser().resolve())

    # Mount browser-harness from host if available (read-only).
    # NOTE: These are NOT added to the manifest (SDK requires relative paths).
    # They are passed as extra bind mounts via _EXTRA_BIND_MOUNTS in docker_client.py.
    _extra_bind_mounts: list[dict[str, str]] = []
    if _BROWSER_HARNESS_HOST.is_dir():
        _extra_bind_mounts.append(
            {
                "host": str(_BROWSER_HARNESS_HOST.resolve()),
                "container": _BROWSER_HARNESS_MOUNT,
            }
        )
        logger.info("Will mount browser-harness from %s", _BROWSER_HARNESS_HOST)
    else:
        logger.warning(
            "browser-harness not found at %s — browser tools unavailable", _BROWSER_HARNESS_HOST
        )

    # Mount browsercode from host if available (read-only).
    if _BROWSERCODE_HOST.is_dir():
        _extra_bind_mounts.append(
            {
                "host": str(_BROWSERCODE_HOST.resolve()),
                "container": _BROWSERCODE_MOUNT,
            }
        )
        logger.info("Will mount browsercode from %s", _BROWSERCODE_HOST)
    else:
        logger.warning("browsercode not found at %s — browsercode unavailable", _BROWSERCODE_HOST)

    # Mount scan pipeline script (required — scan fails without it).
    if _PIPELINE_SCRIPTS_HOST.is_dir():
        _extra_bind_mounts.append(
            {
                "host": str(_PIPELINE_SCRIPTS_HOST.resolve()),
                "container": _PIPELINE_SCRIPTS_MOUNT,
            }
        )
        logger.info("Will mount scripts/ from %s", _PIPELINE_SCRIPTS_HOST)
    else:
        logger.error(
            "scripts/ NOT FOUND at %s — scan pipeline will fail with exit 127",
            _PIPELINE_SCRIPTS_HOST,
        )

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    # Build PYTHONPATH: include browser-harness src if mounted.
    pypath_parts = ["/opt/prometheus-python"]
    if _BROWSER_HARNESS_HOST.is_dir():
        pypath_parts.append(f"{_BROWSER_HARNESS_MOUNT}/src")
    extra_pythonpath = ":".join(pypath_parts)

    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,[IP_ADDRESS]",
                "PYTHONPATH": extra_pythonpath,
                # Browser-harness CDP connection to in-container Chromium.
                "BU_CDP_URL": "http://[IP_ADDRESS]:9222",
                # Tor proxy info, used by scripts like scan-pipeline.sh
                "PROMETHEUS_TOR_PROXY": _TOR_PROXY,
                "PROMETHEUS_ALLOW_DIRECT": str(allow_direct).lower(),
            },
        ),
    )

    # Store extra bind mounts for the Docker client to pick up
    global _pending_extra_bind_mounts  # noqa: PLW0603
    _pending_extra_bind_mounts = _extra_bind_mounts  # codeql[py/unused-global-variable] : suppressed via the security dashboard triage

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    import asyncio

    _max_retries = 3
    _last_exc = None
    client = None
    session = None
    for _attempt in range(1, _max_retries + 1):
        try:
            client, session = await backend(
                image=image,
                manifest=manifest,
                exposed_ports=(_CONTAINER_CAIDO_PORT,),
            )
            break  # success
        except RuntimeError:
            raise  # Already wrapped with context by docker_client
        except Exception as exc:
            _last_exc = exc
            if _attempt < _max_retries:
                _delay = 5 * _attempt
                logger.warning(
                    "Sandbox creation attempt %d/%d failed: %s -- retrying in %ds",
                    _attempt,
                    _max_retries,
                    exc,
                    _delay,
                )
                await asyncio.sleep(_delay)
            else:
                raise RuntimeError(
                    f"Failed to create Docker sandbox after {_max_retries} attempts: {_last_exc}. "
                    f"Is Docker running? Check 'docker info' and 'docker ps'."
                ) from _last_exc

    if session is None:
        raise RuntimeError("Failed to create Docker sandbox: session is None")
    try:
        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to resolve Caido proxy port inside sandbox: {exc}. "
            f"The container may not have started correctly."
        ) from exc

    host_caido_url = f"http://{caido_endpoint.host}:{caido_endpoint.port}"
    logger.debug("Caido host endpoint resolved: %s", host_caido_url)

    caido_client = None
    try:
        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=container_caido_url,
        )
    except Exception as exc:
        logger.warning(
            "Caido proxy bootstrap failed (non-fatal): %s. "
            "Proxy interception tools will be unavailable but the scan continues.",
            exc,
        )

    # --- Browser automation setup ---
    # Install browser-harness deps and start Chromium with CDP.
    if _BROWSER_HARNESS_HOST.is_dir():
        try:
            await _setup_browser_automation(session)
        except Exception as exc:
            logger.warning("Browser automation setup failed (non-fatal): %s", exc)

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.

    If the SDK's ``client.delete`` fails (e.g. because the container
    didn't stop in time), we fall back to a direct Docker stop + force
    remove to avoid leaving stale containers behind.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    try:
        await bundle["client"].delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.warning(
            "cleanup(%s): client.delete raised; attempting forceful container cleanup",
            scan_id,
            exc_info=True,
        )
        _force_cleanup_container(bundle, scan_id)


def _force_cleanup_container(bundle: dict[str, Any], scan_id: str) -> None:
    """Best-effort forceful stop and removal of a sandbox container.

    Used as a fallback when the SDK's ``client.delete`` fails.  Retrieves
    the container ID from the session state and issues direct Docker API
    calls to stop (with retry) and remove (with retry on 409 conflict).

    Phase 2C: the 7 audit runs that hit ``docker.errors.APIError 409
    cannot remove container`` were the container still spinning up
    after ``client.delete`` returned. We now retry ``remove(force=True)``
    up to 3 times with 2-second backoff. We also swallow
    ``docker.errors.NotFound`` so an already-removed container does not
    log a WARNING.
    """
    import docker.errors  # noqa: PLC0415  — kept local so module import

    # doesn't pull the docker SDK at top level
    _ = docker.errors  # silence "imported but unused" warnings

    container_id: str | None = None
    try:
        session = bundle.get("session")
        if session is not None:
            inner = getattr(session, "_inner", None)
            if inner is not None:
                state = getattr(inner, "state", None)
                if state is not None:
                    container_id = getattr(state, "container_id", None)
    except Exception:
        logger.debug("cleanup(%s): failed to extract container_id", scan_id, exc_info=True)

    if not container_id:
        logger.warning("cleanup(%s): no container_id found; cannot force cleanup", scan_id)
        return

    client = bundle.get("client")
    docker_client = getattr(client, "docker_client", None)
    if docker_client is None:
        logger.warning("cleanup(%s): no docker_client available for force cleanup", scan_id)
        return

    # Get the container object (or bail out cleanly if it's already gone).
    try:
        container = docker_client.containers.get(container_id)
    except docker.errors.NotFound:
        logger.info(
            "cleanup(%s): container %s already gone",
            scan_id,
            container_id[:12],
        )
        return
    except Exception:
        logger.info(
            "cleanup(%s): container %s lookup failed; treating as gone",
            scan_id,
            container_id[:12],
            exc_info=True,
        )
        return

    # Stop the container with a 15-second timeout. If it doesn't stop in time,
    # we still proceed to remove(force=True) below — that stops + removes.
    try:
        container.stop(timeout=15)
        logger.info("cleanup(%s): stopped container %s", scan_id, container_id[:12])
    except docker.errors.NotFound:
        logger.info(
            "cleanup(%s): container %s disappeared during stop",
            scan_id,
            container_id[:12],
        )
        return
    except Exception:
        logger.debug(
            "cleanup(%s): container.stop() raised (may already be stopped)",
            scan_id,
            exc_info=True,
        )

    # Retry remove(force=True) up to 3 times on 409 conflict (container still
    # spinning up after client.delete returned, or transient Docker state).
    for _attempt in range(1, 4):
        try:
            container.remove(force=True)
            logger.info(
                "cleanup(%s): removed container %s",
                scan_id,
                container_id[:12],
            )
            return
        except docker.errors.NotFound:
            logger.info(
                "cleanup(%s): container %s already removed",
                scan_id,
                container_id[:12],
            )
            return
        except docker.errors.APIError as exc:
            status = getattr(exc, "status_code", None)
            if status == 409 and _attempt < 3:
                logger.warning(
                    "cleanup(%s): 409 removing %s (attempt %d/3), retrying in 2s",
                    scan_id,
                    container_id[:12],
                    _attempt,
                )
                time.sleep(2.0)
                continue
            logger.warning(
                "cleanup(%s): failed to remove container %s; it may need manual reaping",
                scan_id,
                container_id[:12],
                exc_info=True,
            )
            return
        except Exception:
            logger.warning(
                "cleanup(%s): failed to remove container %s; it may need manual reaping",
                scan_id,
                container_id[:12],
                exc_info=True,
            )
            return
