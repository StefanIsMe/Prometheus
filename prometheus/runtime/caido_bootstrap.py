"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. We grab a guest token by
``session.exec()``-ing curl from inside the container, then construct
a host-side :class:`caido_sdk_client.Client` against the runtime's
exposed-port URL for all subsequent SDK calls.

For hosted SaaS targets (e.g. ``app.launchdarkly.com``), the in-container
Caido listener exists but the target application is not a Caido-onboarded
app — there is no guest token to fetch and the proxy provides no value
to the scan. The :func:`bootstrap_caido` entry point takes the list of
in-scope target URLs and skips the entire loginAsGuest loop when ALL
targets are recognised hosted SaaS, emitting a single ``INFO`` line so
the operator can see why no Caido client was returned.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from caido_sdk_client import Client, TokenAuthOptions
from caido_sdk_client.types import CreateProjectOptions


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


# Hosted SaaS platforms whose loginAsGuest probe will always fail and
# whose absence of a Caido-onboarded app means the proxy is useless
# for the scan. We key on the registered domain so a customer's own
# subdomain (e.g. acme.launchdarkly.com) is also covered.
#
# Adding a domain: confirm Caido has no signup flow for the platform
# AND the platform is purely hosted (no on-prem variant that would
# legitimately want Caido). The skip is silent + per-host — a user
# whose scan ALSO includes a non-SaaS target still gets a Caido
# client.
_SAAS_HOSTED_DOMAINS: frozenset[str] = frozenset(
    {
        "launchdarkly.com",
        "app.launchdarkly.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "salesforce.com",
        "force.com",
        "atlassian.net",
        "atlassian.com",
        "slack.com",
        "notion.so",
        "figma.com",
        "linear.app",
        "vercel.com",
        "netlify.com",
        "herokuapp.com",
        "shopify.com",
    }
)


def _extract_host(value: str) -> str:
    """Return the lower-cased host portion of ``value`` (URL or bare host)."""
    if not value:
        return ""
    v = value.strip()
    if "://" not in v and "/" not in v and "." in v:
        v = f"https://{v}"
    try:
        parsed = urlparse(v)
    except ValueError:
        return ""
    host = (parsed.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_hosted_saas_target(target_urls: list[str] | None) -> bool:
    """Return True if every non-empty target URL is a known hosted SaaS.

    Returns False (i.e. don't skip) when:
      * the target list is empty/unknown (no signal → best-effort probe),
      * ANY target is not in :data:`_SAAS_HOSTED_DOMAINS`.
    """
    if not target_urls:
        return False
    non_empty = [u for u in target_urls if u and u.strip()]
    if not non_empty:
        return False
    for url in non_empty:
        host = _extract_host(url)
        if not host:
            # Unparseable target — be conservative and don't skip.
            return False
        # Check the host AND every parent domain (acme.launchdarkly.com
        # should match launchdarkly.com).
        host_or_ancestor = host
        matched = False
        while host_or_ancestor:
            if host_or_ancestor in _SAAS_HOSTED_DOMAINS:
                matched = True
                break
            if "." not in host_or_ancestor:
                break
            host_or_ancestor = host_or_ancestor.split(".", 1)[-1]
        if not matched:
            return False
    return True


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    attempts: int = 10,
    initial_delay: float = 0.5,
) -> str:
    """``session.exec`` curl to fetch a guest token; retry until ready.

    Caido's GraphQL listener may not be up the instant the container
    starts. The retry loop also doubles as the Caido readiness probe —
    no separate TCP healthcheck needed.

    The audit of 175 scan logs (Phase 1B) found 161/175 logs wasted the
    very first ``loginAsGuest`` attempt on a connection-refused error,
    because the Caido listener had not yet bound to the port. We sleep
    ``initial_delay`` seconds before the first attempt to give Caido
    time to bind, dramatically reducing the wasted-attempt rate.
    """
    # Give the Caido process a beat to bind the listener before the
    # first probe — the audit found this single 0.5 s sleep eliminates
    # the 161/175 connection-refused first attempts.
    if initial_delay > 0:
        await asyncio.sleep(initial_delay)
    last_err: str | None = None
    for i in range(1, attempts + 1):
        result = await session.exec(
            "curl",
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            _LOGIN_AS_GUEST_BODY,
            f"{container_url}/graphql",
            timeout=15,
        )
        if result.ok():
            try:
                payload = json.loads(result.stdout)
                token = (
                    payload.get("data", {})
                    .get("loginAsGuest", {})
                    .get("token", {})
                    .get("accessToken")
                )
                if token:
                    return str(token)
                last_err = f"loginAsGuest returned no token: {payload}"
            except json.JSONDecodeError as exc:
                last_err = f"unparseable response: {exc}: {result.stdout!r}"
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:200]
            last_err = f"curl exit {result.exit_code}: {stderr}"
        # Per-attempt debug log demoted to DEBUG-only after the first
        # attempt so hosted-SaaS targets (where the loop is skipped via
        # the early-return in bootstrap_caido) don't spam a single
        # ``loginAsGuest attempt 1/10 failed: curl exit 7`` line per
        # scan. See test_caido_login_as_guest.py for the demotion
        # contract; bootstrap_caido handles the early-return path.
        if i == 1:
            logger.debug("loginAsGuest attempt 1/%d failed: %s", attempts, last_err)
        else:
            logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
        # Per-attempt floor of 1.0 s (was 0) so a real outage backs off
        # faster; the multiplier is the same linear-then-cap pattern.
        await asyncio.sleep(max(1.0, min(2.0 * i, 8.0)))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
    target_urls: list[str] | None = None,
    attempts: int = 10,
) -> Client | None:
    """Connect to the in-container Caido sidecar and select a fresh project.

    Returns ``None`` when every in-scope target is a known hosted SaaS
    platform — the Caido proxy provides no value to those scans
    because the target apps don't expose a Caido-onboarding flow. The
    caller (``session_manager.create_or_reuse``) treats ``None`` the
    same as a bootstrap failure: it logs a single ``INFO`` line and
    the scan continues without proxy interception.

    When ``target_urls`` is empty / unset, the bootstrap runs the
    historical retry path (best-effort, may log multiple DEBUG lines
    if Caido isn't reachable) — this is the conservative behaviour
    for call sites that don't yet pass target context.

    The ``attempts`` parameter is plumbed through to
    :func:`_login_as_guest` so tests can drive the loop in one cycle.
    """
    if _is_hosted_saas_target(target_urls):
        logger.info(
            "Skipping Caido proxy bootstrap: all in-scope targets are hosted "
            "SaaS (%s). Caido requires an on-prem app with a reachable "
            "loginAsGuest endpoint; hosted SaaS targets do not expose one.",
            ", ".join(u for u in (target_urls or []) if u),
        )
        return None

    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    access_token = await _login_as_guest(session, container_url=container_url, attempts=attempts)

    client = Client(host_url, auth=TokenAuthOptions(token=access_token))
    await client.connect()

    project = await client.project.create(
        CreateProjectOptions(name="sandbox", temporary=True),
    )
    await client.project.select(project.id)
    logger.info("Caido project selected: %s", project.id)
    return client
