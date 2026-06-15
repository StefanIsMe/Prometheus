"""Tests for the LLM budget preflight check.

Background: Phase 3D adds a cheap, fast credits check before the heavy
sandboxes spin up. The audit found 2 runs (one OpenRouter 402, one 429)
that retried the launch until timeout. The preflight refuses to launch
if the account is below the headroom floor (default 50K tokens) and
the runner returns None so the caller can decide what to do.

This file:

  1. Unit-tests that a 402 response from the provider makes the
     preflight return ``(False, ...)``.
  2. Unit-tests that a 429 response from the provider makes the
     preflight return ``(False, ...)``.
  3. Unit-tests that ``x-ratelimit-remaining-tokens`` below the
     headroom floor makes the preflight return ``(False, ...)``.
  4. Unit-tests that a normal 200 response makes the preflight return
     ``(True, ...)``.
  5. Unit-tests that a missing API key makes the preflight return
     ``(True, ...)`` (best-effort, never blocks).
  6. Unit-tests that the failure-to-load-settings path returns
     ``(True, ...)`` (best-effort).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.core.runner import _check_llm_budget  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_settings(
    provider: str = "openai", api_base: str = "https://api.openai.com/v1"
) -> SimpleNamespace:
    return SimpleNamespace(
        llm=SimpleNamespace(provider=provider, api_base=api_base),
    )


def _mock_response(*, status: int, headers: dict[str, str] | None = None, text: str = ""):
    """Build an httpx-like response stand-in for the preflight check."""
    return SimpleNamespace(
        status_code=status,
        headers=headers or {},
        text=text,
    )


# ---------------------------------------------------------------------------
# 1. 402 from provider
# ---------------------------------------------------------------------------


def test_402_makes_preflight_fail():
    """A 402 Payment Required response must make the preflight return False."""

    async def _run() -> None:
        with patch("prometheus.config.load_settings", return_value=_fake_settings()):
            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.get = AsyncMock(
                    return_value=_mock_response(status=402, text="out of credits")
                )
                with patch("httpx.AsyncClient", return_value=mock_client):
                    ok, msg = await _check_llm_budget("scan-test")
        assert ok is False
        assert "402" in msg

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. 429 from provider
# ---------------------------------------------------------------------------


def test_429_makes_preflight_fail():
    """A 429 rate-limit response must make the preflight return False."""

    async def _run() -> None:
        with patch("prometheus.config.load_settings", return_value=_fake_settings()):
            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.get = AsyncMock(
                    return_value=_mock_response(status=429, text="rate limit")
                )
                with patch("httpx.AsyncClient", return_value=mock_client):
                    ok, msg = await _check_llm_budget("scan-test")
        assert ok is False
        assert "429" in msg

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. x-ratelimit-remaining-tokens below headroom
# ---------------------------------------------------------------------------


def test_low_remaining_tokens_makes_preflight_fail():
    """A 200 with ``x-ratelimit-remaining-tokens`` < headroom must fail."""

    async def _run() -> None:
        with patch("prometheus.config.load_settings", return_value=_fake_settings()):
            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.get = AsyncMock(
                    return_value=_mock_response(
                        status=200,
                        headers={"x-ratelimit-remaining-tokens": "100"},
                    )
                )
                with patch("httpx.AsyncClient", return_value=mock_client):
                    ok, msg = await _check_llm_budget("scan-test")
        assert ok is False
        assert "100" in msg

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Normal 200 passes
# ---------------------------------------------------------------------------


def test_normal_200_passes():
    """A 200 with no rate-limit header makes the preflight return True."""

    async def _run() -> None:
        with patch("prometheus.config.load_settings", return_value=_fake_settings()):
            with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.get = AsyncMock(
                    return_value=_mock_response(
                        status=200,
                        headers={"x-ratelimit-remaining-tokens": "10000000"},
                    )
                )
                with patch("httpx.AsyncClient", return_value=mock_client):
                    ok, msg = await _check_llm_budget("scan-test")
        assert ok is True
        assert "OK" in msg

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Missing API key does not block
# ---------------------------------------------------------------------------


def test_missing_api_key_does_not_block():
    """A missing API key in env must NOT block the scan (best-effort)."""

    async def _run() -> None:
        with patch("prometheus.config.load_settings", return_value=_fake_settings()):
            with patch.dict("os.environ", {}, clear=True):
                ok, msg = await _check_llm_budget("scan-test")
        assert ok is True
        assert "no API key" in msg or "skipping" in msg

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. Settings load failure does not block
# ---------------------------------------------------------------------------


def test_settings_load_failure_does_not_block():
    """If ``load_settings`` raises, the preflight must NOT block."""

    async def _run() -> None:
        with patch(
            "prometheus.config.load_settings",
            side_effect=RuntimeError("settings not found"),
        ):
            ok, msg = await _check_llm_budget("scan-test")
        assert ok is True
        assert "skipping" in msg or "failed" in msg

    asyncio.run(_run())
