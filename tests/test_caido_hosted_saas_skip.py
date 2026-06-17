"""Tests for the hosted-SaaS short-circuit in bootstrap_caido.

The launchdarkly scan logged a ``loginAsGuest attempt 1/10 failed:
curl exit 7`` DEBUG line on a target where Caido is never useful —
hosted SaaS platforms don't expose a Caido-onboarding endpoint, so
the proxy is pure overhead. This file pins down the early-return
behaviour and the host detection.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.runtime import caido_bootstrap  # noqa: E402
from prometheus.runtime.caido_bootstrap import (  # noqa: E402
    _is_hosted_saas_target,
    bootstrap_caido,
)


# ---------------------------------------------------------------------------
# Host detection
# ---------------------------------------------------------------------------


def test_saas_detection_matches_known_platform():
    assert _is_hosted_saas_target(["https://app.launchdarkly.com/"]) is True


def test_saas_detection_matches_customer_subdomain():
    """acme.launchdarkly.com should match launchdarkly.com."""
    assert _is_hosted_saas_target(["https://acme.launchdarkly.com/feature/flags"]) is True


def test_saas_detection_matches_bare_host():
    assert _is_hosted_saas_target(["app.launchdarkly.com"]) is True


def test_saas_detection_strips_www_prefix():
    assert _is_hosted_saas_target(["https://www.launchdarkly.com/"]) is True


def test_saas_detection_rejects_unknown_target():
    assert _is_hosted_saas_target(["https://acme-corp.example.com/"]) is False


def test_saas_detection_rejects_mixed_targets():
    """If ANY target is not a known SaaS, don't skip — the operator may
    want Caido for the non-SaaS target even if the SaaS targets are
    noise."""
    assert (
        _is_hosted_saas_target(
            [
                "https://app.launchdarkly.com/",
                "https://acme-corp.example.com/",
            ]
        )
        is False
    )


def test_saas_detection_handles_empty_list():
    """Empty list → don't skip (no signal)."""
    assert _is_hosted_saas_target([]) is False
    assert _is_hosted_saas_target(None) is False


def test_saas_detection_skips_blank_entries():
    assert _is_hosted_saas_target(["", "  ", "https://app.launchdarkly.com/"]) is True


# ---------------------------------------------------------------------------
# bootstrap_caido early-return
# ---------------------------------------------------------------------------


class _FakeSession:
    """A session that would explode if any exec call were made."""

    def __init__(self) -> None:
        self.exec_called = False

    async def exec(self, *args, **kwargs):  # pragma: no cover - never reached
        self.exec_called = True
        raise AssertionError("session.exec must NOT be called when target is hosted SaaS")


def test_bootstrap_skips_when_all_targets_are_saas(caplog):
    session = _FakeSession()
    with caplog.at_level(logging.INFO, logger="prometheus.runtime.caido_bootstrap"):
        result = asyncio.run(
            bootstrap_caido(
                session,
                host_url="http://caido-host:48080",
                container_url="http://127.0.0.1:48080",
                target_urls=["https://app.launchdarkly.com/"],
            )
        )
    assert result is None
    assert session.exec_called is False
    # The skip must be visible at INFO so an operator can grep for it
    # without flipping the log level.
    skip_msgs = [r.message for r in caplog.records if "Skipping Caido" in r.message]
    assert skip_msgs, "expected an INFO 'Skipping Caido' line"


def test_bootstrap_runs_when_target_is_not_saas():
    """If the target list contains a non-SaaS URL, the historical
    retry path must run. We can't drive the success path here without
    a real Caido sidecar, so we just confirm the early-return DID NOT
    fire and the session was used."""
    session = SimpleNamespace()
    exec_calls: list[tuple] = []

    async def fake_exec(*args, **kwargs):
        exec_calls.append(args)
        # Simulate the connection-refused first attempt. We just need
        # to confirm exec was called — the full retry loop is covered
        # by test_caido_login_as_guest.py.
        from tests.test_caido_login_as_guest import _FakeResult  # type: ignore

        return _FakeResult(ok=False, stderr=b"connection refused", exit_code=7)

    session.exec = fake_exec

    # 1 attempt + initial_delay=0 so the test is fast; the bootstrap
    # will then raise RuntimeError from _login_as_guest, which we
    # catch.
    async def fake_sleep(_s):
        return None

    with patch.object(caido_bootstrap.asyncio, "sleep", new=fake_sleep):
        with pytest.raises(RuntimeError):
            asyncio.run(
                bootstrap_caido(
                    session,
                    host_url="http://caido-host:48080",
                    container_url="http://127.0.0.1:48080",
                    target_urls=["https://acme-corp.example.com/"],
                    attempts=1,
                )
            )
    assert exec_calls, "session.exec must be called for non-SaaS targets"


def test_bootstrap_runs_when_target_urls_is_none():
    """Conservative behaviour: an empty / missing target list is NOT
    a signal that the target is hosted SaaS. Bootstrap must run the
    historical retry path."""
    session = SimpleNamespace()

    async def fake_exec(*args, **kwargs):
        from tests.test_caido_login_as_guest import _FakeResult  # type: ignore

        return _FakeResult(ok=False, stderr=b"connection refused", exit_code=7)

    session.exec = fake_exec

    async def fake_sleep(_s):
        return None

    with patch.object(caido_bootstrap.asyncio, "sleep", new=fake_sleep):
        with pytest.raises(RuntimeError):
            asyncio.run(
                bootstrap_caido(
                    session,
                    host_url="http://caido-host:48080",
                    container_url="http://127.0.0.1:48080",
                    target_urls=None,
                    attempts=1,
                )
            )


def test_bootstrap_runs_when_target_list_empty_strings():
    """All-blank target list → no signal → don't skip."""
    session = SimpleNamespace()

    async def fake_exec(*args, **kwargs):
        from tests.test_caido_login_as_guest import _FakeResult  # type: ignore

        return _FakeResult(ok=False, stderr=b"connection refused", exit_code=7)

    session.exec = fake_exec

    async def fake_sleep(_s):
        return None

    with patch.object(caido_bootstrap.asyncio, "sleep", new=fake_sleep):
        with pytest.raises(RuntimeError):
            asyncio.run(
                bootstrap_caido(
                    session,
                    host_url="http://caido-host:48080",
                    container_url="http://127.0.0.1:48080",
                    target_urls=["", "  "],
                    attempts=1,
                )
            )


def test_bootstrap_skips_at_info_not_warning(caplog):
    """The skip is expected behaviour, not a fault — must log at INFO."""
    session = _FakeSession()
    with caplog.at_level(logging.DEBUG, logger="prometheus.runtime.caido_bootstrap"):
        asyncio.run(
            bootstrap_caido(
                session,
                host_url="http://caido-host:48080",
                container_url="http://127.0.0.1:48080",
                target_urls=["https://app.launchdarkly.com/"],
            )
        )
    skip_records = [r for r in caplog.records if "Skipping Caido" in r.message]
    assert skip_records
    for r in skip_records:
        assert r.levelno == logging.INFO, (
            f"skip should be INFO, got {logging.getLevelName(r.levelno)}"
        )
