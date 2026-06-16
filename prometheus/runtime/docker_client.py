"""PrometheusDockerSandboxClient — preserves the image's ENTRYPOINT and adds
NET_ADMIN/NET_RAW capabilities + host-gateway.

The SDK's ``DockerSandboxClient._create_container`` does not expose a hook for
extending ``create_kwargs`` before ``containers.create`` is called. We subclass
and reimplement the method body verbatim from the SDK source, with three
deltas:

1. Drop the SDK's ``entrypoint=["tail"]`` override; supply ``["tail", "-f",
   "/dev/null"]`` as ``command`` instead. This lets our image's
   ``docker-entrypoint.sh`` actually run — without it, ``caido-cli`` never
   starts inside the container and ``bootstrap_caido`` retries against a
   dead port.
2. Append NET_ADMIN/NET_RAW to ``cap_add`` (required by ``nmap -sS`` and
   other raw-socket tools).
3. Add ``host.docker.internal`` → host-gateway to ``extra_hosts`` so the
   agent can reach host-served apps.

Pinned to ``openai-agents==0.14.6``. Bumping the SDK requires
re-merging the parent body. Track upstream for an injection hook.
"""

from __future__ import annotations

import logging
import subprocess
import time
import uuid
from typing import Any

from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClient,
    _build_docker_volume_mounts,
    _docker_port_key,
    _manifest_requires_fuse,
    _manifest_requires_sys_admin,
)
from docker.models.containers import Container  # type: ignore[import-untyped, unused-ignore]
from docker.utils import parse_repository_tag  # type: ignore[import-untyped, unused-ignore]


logger = logging.getLogger(__name__)

# Tor SOCKS5 proxy address — reachable from containers via Docker's host-gateway.
_TOR_PROXY = "socks5://host.docker.internal:9050"

# Docker connectivity errors that indicate a daemon restart might help.
_DOCKER_RECOVERABLE_ERRORS: tuple[type[Exception], ...] = (
    TimeoutError,
    ConnectionError,
    OSError,
)
try:
    import requests.exceptions
    from urllib3.exceptions import TimeoutError as Urllib3Timeout

    _DOCKER_RECOVERABLE_ERRORS = (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        Urllib3Timeout,
        TimeoutError,
        ConnectionError,
        OSError,
    )
except ImportError:
    logger.debug("optional timeout/connection imports unavailable, ignoring", exc_info=True)


def _is_docker_alive() -> bool:
    """Check if Docker daemon responds to a lightweight ping."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _restart_docker_daemon() -> bool:
    """Restart Docker daemon and wait for it to become responsive.

    Returns True if Docker is alive after restart, False otherwise.
    """
    logger.warning("Attempting Docker daemon restart (sudo systemctl restart docker)...")
    try:
        subprocess.run(
            ["sudo", "systemctl", "restart", "docker"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.error("Docker restart command failed: %s", exc)
        return False
    # Wait for Docker to become responsive (up to 15s).
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _is_docker_alive():
            logger.info("Docker daemon restarted successfully")
            return True
        time.sleep(1)
    logger.error("Docker daemon did not become responsive after restart")
    return False


def _inject_tor_proxy(
    environment: dict[str, str] | list[str] | None,
) -> dict[str, str]:
    """Add tor proxy and allow-direct info to the container environment.

    session_manager.py seeds system proxy vars to the in-container Caido
    intercepting proxy (tool -> Caido -> ...). This function does NOT
    override those — it adds PROMETHEUS_TOR_PROXY and PROMETHEUS_ALLOW_DIRECT
    as *additional* env vars so tools and scripts inside the container can
    choose to use Tor explicitly.

    The traffic flow is:  tool -> Caido (recording) -> Tor -> internet
    Caido itself is wrapped with torsocks in docker-entrypoint.sh.
    """
    if environment is None:
        env_dict: dict[str, str] = {}
    elif isinstance(environment, list):
        env_dict = dict(e.split("=", 1) for e in environment if "=" in e)
    else:
        env_dict = dict(environment)

    # Keep system proxy vars pointing to Caido (set by session_manager manifest).
    # DON'T override them to Tor — Caido's torsocks wrapper handles that.
    # Instead, add Tor info as separate env vars for tools that need it.
    env_dict["PROMETHEUS_TOR_PROXY"] = _TOR_PROXY
    env_dict.setdefault("NO_PROXY", "localhost,[IP_ADDRESS]")
    # PROMETHEUS_ALLOW_DIRECT is already set by session_manager manifest; preserve if present.
    env_dict.setdefault("PROMETHEUS_ALLOW_DIRECT", "false")

    logger.info("Tor proxy info injected: %s (proxy vars kept pointing to Caido)", _TOR_PROXY)
    return env_dict


def _exc_chain_types(exc: BaseException) -> set[type[BaseException]]:
    """Walk an exception's __cause__ / __context__ chain and return all types."""
    seen: set[int] = set()
    types: set[type[BaseException]] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        types.add(type(current))
        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__context__ is not current:
            current = current.__context__
        else:
            current = None
    return types


class PrometheusDockerSandboxClient(DockerSandboxClient):
    """Docker sandbox client with NET_ADMIN/NET_RAW caps and self-healing.

    On Docker connectivity errors (daemon hung, socket timeout), attempts to
    restart the Docker daemon and retry once before raising an error.
    """

    async def _create_container(
        self,
        image: str,
        *,
        manifest: Manifest | None = None,
        exposed_ports: tuple[int, ...] = (),
        session_id: uuid.UUID | None = None,
    ) -> Container:
        """Create a sandbox container with automatic Docker recovery."""
        try:
            return await _create_container_impl(
                self,
                image,
                manifest=manifest,
                exposed_ports=exposed_ports,
                session_id=session_id,
            )
        except Exception as exc:
            return await _recover_and_retry(
                exc,
                self,
                image,
                manifest=manifest,
                exposed_ports=exposed_ports,
                session_id=session_id,
            )


async def _create_container_impl(
    client: PrometheusDockerSandboxClient,
    image: str,
    *,
    manifest: Manifest | None = None,
    exposed_ports: tuple[int, ...] = (),
    session_id: uuid.UUID | None = None,
) -> Container:
    """Core container creation logic (verbatim from SDK, with prometheus deltas)."""
    # ----- BEGIN VERBATIM COPY of DockerSandboxClient._create_container -----
    # SDK ref: src/agents/sandbox/sandboxes/docker.py:1434-1477 (v0.14.6).
    if not client.image_exists(image):
        repo, tag = parse_repository_tag(image)
        try:
            client.docker_client.images.pull(repo, tag=tag or None, all_tags=False)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to pull Docker image '{image}': {exc}. "
                f"Check your network or run 'docker pull {image}' manually."
            ) from exc

    if not client.image_exists(image):
        raise RuntimeError(
            f"Docker image '{image}' not found after pull attempt. "
            f"Run 'docker pull {image}' manually to diagnose."
        )
    environment: dict[str, str] | None = None
    if manifest:
        environment = await manifest.environment.resolve()
    # prometheus delta from the SDK body: drop ``entrypoint`` override and
    # supply ``tail -f /dev/null`` as ``command`` so the image's
    # ENTRYPOINT (``docker-entrypoint.sh``) runs setup, then ``exec
    # "$@"`` becomes ``exec tail -f /dev/null`` for the keep-alive.
    # Without this, caido-cli + the in-container CA trust never get
    # initialized.
    create_kwargs: dict[str, Any] = {
        "image": image,
        "detach": True,
        "command": ["tail", "-f", "/dev/null"],
        "environment": environment,
    }
    if manifest is not None:
        docker_mounts = _build_docker_volume_mounts(
            manifest,
            session_id=session_id,
        )
        if docker_mounts:
            create_kwargs["mounts"] = docker_mounts
        if _manifest_requires_fuse(manifest):
            create_kwargs.update(
                devices=["/dev/fuse"],
                cap_add=["SYS_ADMIN"],
                security_opt=["apparmor:unconfined"],
            )
        elif _manifest_requires_sys_admin(manifest):
            create_kwargs.update(
                cap_add=["SYS_ADMIN"],
                security_opt=["apparmor:unconfined"],
            )
    if exposed_ports:
        create_kwargs["ports"] = {
            _docker_port_key(port): ("127.0.0.1", None) for port in exposed_ports
        }
    # ----- END VERBATIM COPY -----

    # prometheus injections — append, don't overwrite, so FUSE/SYS_ADMIN survives.
    cap_add = create_kwargs.setdefault("cap_add", [])
    if not isinstance(cap_add, list):
        cap_add = list(cap_add)
        create_kwargs["cap_add"] = cap_add
    for cap in ("NET_ADMIN", "NET_RAW"):
        if cap not in cap_add:
            cap_add.append(cap)

    extra_hosts = create_kwargs.setdefault("extra_hosts", {})
    extra_hosts["host.docker.internal"] = "host-gateway"

    # --- Inject extra bind mounts from session_manager (browser-harness, etc.) ---
    from prometheus.runtime.session_manager import _pending_extra_bind_mounts

    if _pending_extra_bind_mounts:
        existing_mounts = create_kwargs.get("mounts", [])
        for bm in _pending_extra_bind_mounts:
            from docker.types import Mount as DockerMount

            existing_mounts.append(
                DockerMount(
                    target=bm["container"],
                    source=bm["host"],
                    type="bind",
                    read_only=True,
                )
            )
        if existing_mounts:
            create_kwargs["mounts"] = existing_mounts
        logger.info("Injected %d extra bind mounts", len(_pending_extra_bind_mounts))

    # --- Tor proxy injection (OVERRIDE, not setdefault) ---
    create_kwargs["environment"] = _inject_tor_proxy(
        create_kwargs.get("environment"),
    )

    logger.debug(
        "Creating sandbox container: image=%s caps=%s exposed_ports=%s",
        image,
        cap_add,
        list(exposed_ports),
    )
    container = client.docker_client.containers.create(**create_kwargs)
    logger.info(
        "Sandbox container created: id=%s image=%s",
        container.short_id if hasattr(container, "short_id") else "?",
        image,
    )
    return container


async def _recover_and_retry(
    exc: Exception,
    client: PrometheusDockerSandboxClient,
    image: str,
    *,
    manifest: Manifest | None = None,
    exposed_ports: tuple[int, ...] = (),
    session_id: uuid.UUID | None = None,
) -> Container:
    """Attempt Docker daemon restart on connectivity errors, then retry once.

    Raises RuntimeError if the error is non-recoverable, restart fails, or
    the retry also fails.
    """
    chain_types = _exc_chain_types(exc)
    is_recoverable = bool(chain_types & set(_DOCKER_RECOVERABLE_ERRORS))

    if not is_recoverable:
        exc_type = type(exc).__name__
        raise RuntimeError(
            f"Docker container creation failed ({exc_type}): {exc}. "
            f"Is Docker running? Try 'docker info' to check."
        ) from exc

    logger.warning(
        "Docker connectivity error detected (%s), attempting daemon restart...",
        type(exc).__name__,
    )
    if not _restart_docker_daemon():
        exc_type = type(exc).__name__
        raise RuntimeError(
            f"Docker container creation failed ({exc_type}): {exc}. "
            f"Docker daemon restart was attempted but failed. "
            f"Is Docker running? Try 'docker info' to check."
        ) from exc

    logger.info("Retrying container creation after Docker restart...")
    try:
        return await _create_container_impl(
            client,
            image,
            manifest=manifest,
            exposed_ports=exposed_ports,
            session_id=session_id,
        )
    except Exception as retry_exc:
        retry_type = type(retry_exc).__name__
        raise RuntimeError(
            f"Docker container creation failed after daemon restart "
            f"({retry_type}): {retry_exc}. "
            f"Try 'docker info' to diagnose."
        ) from retry_exc
