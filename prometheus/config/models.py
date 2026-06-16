"""SDK model configuration helpers.

Prometheus owns its model routing via prometheus.config.llm_config.
No Hermes dependency.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from agents.retry import ModelRetryBackoffSettings, ModelRetrySettings, retry_policies

from prometheus.config.llm_config import (
    ResolvedModel,
    apply_model_to_sdk,
    get_config,
    resolve_model,
    resolve_tier,
)

if TYPE_CHECKING:
    from prometheus.config.settings import Settings

logger = logging.getLogger(__name__)

_SDK_PREFIXES = {"any-llm", "litellm", "openai"}

DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=3,
    backoff=ModelRetryBackoffSettings(
        initial_delay=1.0,
        max_delay=30.0,
        multiplier=2.0,
        jitter=True,
    ),
    policy=retry_policies.any(
        retry_policies.network_error(),
        retry_policies.retry_after(),
        retry_policies.provider_suggested(),
        retry_policies.http_status({408, 409, 425, 429, 500, 502, 503, 504}),
    ),
)

# Global resolved model (set at scan start)
_current_resolution: ResolvedModel | None = None


def _patch_httpx_no_zstd() -> None:
    """Avoid advertising zstd to OpenAI-compatible gateways."""
    os.environ.setdefault("OPENAI_DISABLE_ZSTD", "1")


def configure_sdk_model_defaults(
    settings: Settings | None = None,
) -> ResolvedModel:
    """Configure the OpenAI Agents SDK from Prometheus LLM config.

    Resolves a model from ~/.prometheus/llm.yaml for the scan's tier.
    No Hermes dependency.

    Args:
        settings: Prometheus settings object (updated in-place).
    """
    global _current_resolution

    config = get_config()
    tier = resolve_tier()
    resolution = resolve_model(config, tier=tier)
    apply_model_to_sdk(resolution)
    _current_resolution = resolution

    logger.info(
        "Prometheus LLM: provider=%s model=%s base_url=%s tier=%s",
        resolution.provider_name,
        resolution.model_id,
        resolution.base_url,
        resolution.tier.value,
    )

    # Update settings for backward compatibility (runner reads settings.llm.model)
    if settings is not None and getattr(settings, "llm", None) is not None:
        settings.llm.model = resolution.model_id
        settings.llm.api_base = resolution.base_url
        settings.llm.api_key = resolution.api_key

    return resolution


def get_active_model_resolution() -> ResolvedModel | None:
    """Return the current model resolution, or None if not yet configured."""
    return _current_resolution


def get_child_agent_resolution() -> ResolvedModel | None:
    """Resolve a model for a child agent (always SIMPLE tier).

    Returns None if resolution fails (caller can fall back to root model).
    """
    try:
        config = get_config()
        return resolve_model(config, tier=resolve_tier(is_child=True))
    except Exception as exc:
        logger.warning("Child agent model resolution failed: %s", exc)
        return None


def normalize_model_name(model: str | None) -> str:
    """Normalize model IDs for the OpenAI Agents SDK MultiProvider."""
    name = (model or "").strip()
    if not name:
        return ""
    if "/" not in name:
        return name
    prefix = name.split("/", 1)[0]
    if prefix in _SDK_PREFIXES:
        return name
    return name


def uses_chat_completions_tool_schema(model: str | None, settings: Settings | None = None) -> bool:
    """Return True when tools should use Chat Completions compatible schemas."""
    normalized = normalize_model_name(model).lower()
    if normalized.startswith(("litellm/", "any-llm/")):
        return True

    base_url = ""
    if settings is not None and getattr(settings, "llm", None) is not None:
        base_url = str(settings.llm.api_base or "").lower()
    if not base_url:
        base_url = os.environ.get("OPENAI_BASE_URL", "").lower()

    if base_url and "api.openai.com" not in base_url:
        return True
    return False
