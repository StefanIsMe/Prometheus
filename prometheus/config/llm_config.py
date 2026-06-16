"""
Native LLM provider/model configuration for Prometheus.

Replaces the Hermes bridge. Prometheus owns its model routing.
Config lives at ~/.prometheus/llm.yaml.

Architecture:
  1. Providers declare base_url, protocol, API keys, available models
  2. Router maps model tiers (simple/hard) to model candidates
  3. Runner resolves a model at scan start, falls back on failure
  4. Anthropic-protocol providers are auto-converted to OpenAI Chat-Completions
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = Path.home() / ".prometheus" / "llm.yaml"

# Env vars the OpenAI Agents SDK reads at client-construction time.
# We wipe these before setting so stale shell values don't leak in.
_OPENAI_CLIENT_ENV_VARS = (
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "LLM_API_BASE",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "OPENAI_API_KEY",
    "LLM_API_KEY",
    "OPENAI_API_TYPE",
    "OPENAI_ORGANIZATION",
    "OPENAI_DISABLE_ZSTD",
)

# Providers whose base_url speaks Anthropic Messages API natively.
# Used to detect when we need to rewrite the base_url to an
# OpenAI-compatible path or use a protocol adapter.
_ANTHROPIC_HOST_MARKERS = ("anthropic.com", "/anthropic")

# Providers that expose BOTH Anthropic and OpenAI on the same host.
# When the config points at the Anthropic path, we rewrite to the
# OpenAI Chat-Completions path automatically.
_DUAL_PROTOCOL_OVERRIDES: dict[str, str] = {
    "minimax": "https://api.minimax.io/v1",
    "minimax-oauth": "https://api.minimax.io/v1",
}

# Known API key env var names per provider.
_PROVIDER_ENV_KEY_MAP: dict[str, str] = {
    "deepseek": "DEEPSEEK_API_KEY",
    "nous": "NOUS_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openai-codex": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "novita": "NOVITA_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
    "xai": "XAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
    "fireworks": "FIREWORKS_API_KEY",
    "deepinfra": "DEEPINFRA_API_KEY",
    "cerebras": "CEREBRAS_API_KEY",
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class Protocol(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


class Tier(str, Enum):
    SIMPLE = "simple"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass
class ModelSpec:
    """A specific model on a specific provider."""

    provider_name: str
    model_id: str
    tier: Tier = Tier.MEDIUM
    max_tokens: int = 8192
    supports_thinking: bool = False


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    protocol: Protocol = Protocol.OPENAI
    api_keys: list[str] = field(default_factory=list)  # resolved key values
    models: dict[str, ModelSpec] = field(default_factory=dict)
    extra_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class TierRouting:
    """Ordered list of (provider_name, model_id) to try for a tier."""

    candidates: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class LlmConfig:
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    routing: dict[Tier, TierRouting] = field(default_factory=dict)
    default_tier: Tier = Tier.MEDIUM
    config_path: Path | None = None


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _resolve_api_key(entry: dict[str, Any] | str) -> str | None:
    """Resolve an API key entry from config.

    Supports:
      - env: ENV_VAR_NAME  → reads from os.environ
      - key: sk-xxxx       → raw key (inline)
      - "sk-xxxx" (string) → raw key shorthand
    """
    if isinstance(entry, str):
        return entry.strip() or None
    if isinstance(entry, dict):
        env_var = entry.get("env")
        if env_var:
            return os.environ.get(str(env_var))
        raw_key = entry.get("key")
        if raw_key:
            return str(raw_key)
    return None


def _is_anthropic_base_url(base_url: str) -> bool:
    haystack = base_url.lower()
    return any(m in haystack for m in _ANTHROPIC_HOST_MARKERS)


def _rewrite_dual_protocol(provider_name: str, base_url: str) -> str:
    """If provider exposes both Anthropic and OpenAI paths, rewrite to OpenAI."""
    key = provider_name.lower()
    override = _DUAL_PROTOCOL_OVERRIDES.get(key)
    if override and _is_anthropic_base_url(base_url):
        logger.info(
            "Provider %s base_url %s is Anthropic-protocol, rewriting to OpenAI-compatible %s",
            provider_name,
            base_url,
            override,
        )
        return override
    return base_url


def load_llm_config(path: Path | None = None) -> LlmConfig:
    """Load LLM configuration from YAML file.

    If path is None, tries:
      1. PROMETHEUS_LLM_CONFIG env var
      2. ~/.prometheus/llm.yaml
    """
    if path is None:
        env_path = os.environ.get("PROMETHEUS_LLM_CONFIG")
        if env_path:
            path = Path(env_path)
        else:
            path = DEFAULT_CONFIG_PATH

    if not path.is_file():
        logger.warning("LLM config not found at %s, using built-in defaults", path)
        return _build_default_config()

    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        logger.error("Failed to load LLM config from %s: %s", path, exc)
        return _build_default_config()

    return _parse_config(raw, path)


def _parse_config(raw: dict[str, Any], path: Path) -> LlmConfig:
    """Parse raw YAML into LlmConfig."""
    providers: dict[str, ProviderConfig] = {}
    routing: dict[Tier, TierRouting] = {}

    # Parse providers
    providers_raw = raw.get("providers", {})
    if isinstance(providers_raw, dict):
        for name, pdata in providers_raw.items():
            if not isinstance(pdata, dict):
                continue
            pdata = dict(pdata)  # type narrowing

            base_url = str(pdata.get("base_url", "")).strip()
            if not base_url:
                logger.warning("Provider %s has no base_url, skipping", name)
                continue

            protocol_str = str(pdata.get("protocol", "openai")).lower()
            try:
                protocol = Protocol(protocol_str)
            except ValueError:
                logger.warning(
                    "Unknown protocol '%s' for provider %s, defaulting to openai",
                    protocol_str,
                    name,
                )
                protocol = Protocol.OPENAI

            # Rewrite dual-protocol base_urls
            base_url = _rewrite_dual_protocol(name, base_url)

            # Resolve API keys
            api_keys_raw = pdata.get("api_keys", [])
            if isinstance(api_keys_raw, list):
                api_keys = []
                for entry in api_keys_raw:
                    key = _resolve_api_key(entry)
                    if key:
                        api_keys.append(key)
            else:
                # Single key as string
                key = _resolve_api_key(api_keys_raw)
                api_keys = [key] if key else []

            # If no keys from config, try env var convention
            if not api_keys:
                env_name = _PROVIDER_ENV_KEY_MAP.get(name.lower())
                if env_name:
                    env_val = os.environ.get(env_name)
                    if env_val:
                        api_keys.append(env_val)

            # Fallback: Nous OAuth token from auth store
            if not api_keys and name.lower() == "nous":
                try:
                    from prometheus.config.nous_oauth import (
                        is_nous_oauth_configured,
                        get_nous_api_key_from_oauth,
                    )

                    if is_nous_oauth_configured():
                        oauth_key = get_nous_api_key_from_oauth()
                        if oauth_key:
                            api_keys.append(oauth_key)
                            logger.info("Nous provider: resolved API key from OAuth store")
                except Exception as exc:
                    logger.debug("Nous OAuth fallback failed: %s", exc)

            # Extra headers
            extra_headers = {}
            headers_raw = pdata.get("extra_headers", {})
            if isinstance(headers_raw, dict):
                extra_headers = {str(k): str(v) for k, v in headers_raw.items()}

            # Parse models
            models: dict[str, ModelSpec] = {}
            models_raw = pdata.get("models", {})
            if isinstance(models_raw, dict):
                for model_id, mdata in models_raw.items():
                    if isinstance(mdata, dict):
                        tier_str = str(mdata.get("tier", "medium")).lower()
                        try:
                            tier = Tier(tier_str)
                        except ValueError:
                            tier = Tier.MEDIUM
                        models[str(model_id)] = ModelSpec(
                            provider_name=name,
                            model_id=str(model_id),
                            tier=tier,
                            max_tokens=int(mdata.get("max_tokens", 8192)),
                            supports_thinking=bool(mdata.get("supports_thinking", False)),
                        )
                    elif isinstance(mdata, str):
                        # Shorthand: model_id: tier
                        try:
                            tier = Tier(str(mdata).lower())
                        except ValueError:
                            tier = Tier.MEDIUM
                        models[str(model_id)] = ModelSpec(
                            provider_name=name,
                            model_id=str(model_id),
                            tier=tier,
                        )

            providers[name] = ProviderConfig(
                name=name,
                base_url=base_url,
                protocol=protocol,
                api_keys=api_keys,
                models=models,
                extra_headers=extra_headers,
            )

    # Parse routing
    routing_raw = raw.get("routing", {})
    if isinstance(routing_raw, dict):
        for tier_name, tier_data in routing_raw.items():
            try:
                tier = Tier(str(tier_name).lower())
            except ValueError:
                continue
            candidates: list[tuple[str, str]] = []
            if isinstance(tier_data, dict):
                models_list = tier_data.get("models", [])
            elif isinstance(tier_data, list):
                models_list = tier_data
            else:
                models_list = []

            for entry in models_list:
                if isinstance(entry, dict):
                    provider = str(entry.get("provider", ""))
                    model = str(entry.get("model", ""))
                    if provider and model:
                        candidates.append((provider, model))
                elif isinstance(entry, str) and "/" in entry:
                    # Shorthand: provider/model
                    provider, model = entry.split("/", 1)
                    candidates.append((provider, model))
            routing[tier] = TierRouting(candidates=candidates)

    # Parse defaults
    default_tier_str = str(raw.get("defaults", {}).get("tier", "medium")).lower()
    try:
        default_tier = Tier(default_tier_str)
    except ValueError:
        default_tier = Tier.MEDIUM

    # If no routes defined, auto-build from model tiers
    if not routing:
        routing = _auto_build_routing(providers)

    config = LlmConfig(
        providers=providers,
        routing=routing,
        default_tier=default_tier,
        config_path=path,
    )
    _validate_config(config)
    return config


def _auto_build_routing(providers: dict[str, ProviderConfig]) -> dict[Tier, TierRouting]:
    """Auto-build routing from model tier annotations."""
    by_tier: dict[Tier, list[tuple[str, str]]] = defaultdict(list)
    for pname, p in providers.items():
        for model_id, spec in p.models.items():
            by_tier[spec.tier].append((pname, model_id))
    return {tier: TierRouting(candidates=models) for tier, models in by_tier.items()}


def _validate_config(config: LlmConfig) -> None:
    """Log warnings for missing keys, unknown providers in routing, etc."""
    for tier, routing in config.routing.items():
        for provider_name, model_id in routing.candidates:
            if provider_name not in config.providers:
                logger.warning(
                    "Routing tier %s references unknown provider %r",
                    tier.value,
                    provider_name,
                )
            elif model_id not in config.providers[provider_name].models:
                logger.warning(
                    "Routing tier %s references unknown model %r on provider %r",
                    tier.value,
                    model_id,
                    provider_name,
                )


def _build_default_config() -> LlmConfig:
    """Built-in default config when no ~/.prometheus/llm.yaml exists.

    Uses DeepSeek if DEEPSEEK_API_KEY is set in ~/.prometheus/.env.
    """
    providers: dict[str, ProviderConfig] = {}

    # DeepSeek — primary provider
    deepseek_keys: list[str] = []
    if os.environ.get("DEEPSEEK_API_KEY"):
        deepseek_keys.append(os.environ["DEEPSEEK_API_KEY"])
    providers["deepseek"] = ProviderConfig(
        name="deepseek",
        base_url="https://api.deepseek.com/v1",
        protocol=Protocol.OPENAI,
        api_keys=deepseek_keys,
        models={
            "deepseek-v4-flash": ModelSpec(
                "deepseek", "deepseek-v4-flash", Tier.SIMPLE, max_tokens=8192
            ),
            "deepseek-v4-pro": ModelSpec(
                "deepseek", "deepseek-v4-pro", Tier.HARD, max_tokens=8192, supports_thinking=True
            ),
        },
    )

    routing = {
        Tier.SIMPLE: TierRouting(
            candidates=[
                ("deepseek", "deepseek-v4-flash"),
            ]
        ),
        Tier.MEDIUM: TierRouting(
            candidates=[
                ("deepseek", "deepseek-v4-flash"),
            ]
        ),
        Tier.HARD: TierRouting(
            candidates=[
                ("deepseek", "deepseek-v4-pro"),
                ("deepseek", "deepseek-v4-flash"),
            ]
        ),
    }

    return LlmConfig(
        providers=providers,
        routing=routing,
        default_tier=Tier.MEDIUM,
    )


# ---------------------------------------------------------------------------
# Model resolution
# ---------------------------------------------------------------------------


@dataclass
class ResolvedModel:
    """A fully resolved model ready for the OpenAI Agents SDK."""

    provider_name: str
    model_id: str
    base_url: str
    api_key: str
    protocol: Protocol
    supports_thinking: bool
    extra_headers: dict[str, str]
    tier: Tier


class ModelResolutionError(RuntimeError):
    """No usable model could be resolved."""


# Track per-key failures for circuit-breaking
_key_failures: dict[str, list[float]] = defaultdict(list)
_KEY_FAILURE_WINDOW = 60.0  # seconds
_KEY_FAILURE_THRESHOLD = 3  # failures in window → circuit break


def _record_key_failure(provider_name: str, api_key: str) -> None:
    """Record a key failure for circuit breaking."""
    now = time.monotonic()
    key_id = f"{provider_name}:{api_key[:8]}"
    _key_failures[key_id].append(now)
    # Prune old failures
    _key_failures[key_id] = [t for t in _key_failures[key_id] if now - t < _KEY_FAILURE_WINDOW]


def _is_key_circuit_broken(provider_name: str, api_key: str) -> bool:
    """Check if a key has failed too many times recently."""
    key_id = f"{provider_name}:{api_key[:8]}"
    now = time.monotonic()
    recent = [t for t in _key_failures[key_id] if now - t < _KEY_FAILURE_WINDOW]
    return len(recent) >= _KEY_FAILURE_THRESHOLD


def resolve_model(
    config: LlmConfig,
    tier: Tier | None = None,
    *,
    exclude_providers: set[str] | None = None,
    exclude_keys: set[str] | None = None,
) -> ResolvedModel:
    """Resolve a model for the given tier.

    Tries each candidate in the tier's routing list. For each candidate,
    tries each API key. Skips circuit-broken keys.

    Raises ModelResolutionError if nothing works.
    """
    tier = tier or config.default_tier
    excluded = exclude_providers or set()
    excluded_keys = exclude_keys or set()

    routing = config.routing.get(tier)
    if not routing or not routing.candidates:
        # Fall back to any available tier
        for fallback_tier in (Tier.MEDIUM, Tier.SIMPLE, Tier.HARD):
            if fallback_tier != tier and fallback_tier in config.routing:
                routing = config.routing[fallback_tier]
                if routing and routing.candidates:
                    logger.warning(
                        "No models for tier %s, falling back to tier %s",
                        tier.value,
                        fallback_tier.value,
                    )
                    break

    if not routing or not routing.candidates:
        raise ModelResolutionError(
            f"No model candidates configured for tier {tier.value}. "
            f"Check ~/.prometheus/llm.yaml routing section."
        )

    errors: list[str] = []

    for provider_name, model_id in routing.candidates:
        if provider_name in excluded:
            continue

        provider = config.providers.get(provider_name)
        if not provider:
            errors.append(f"Unknown provider '{provider_name}' in routing")
            continue

        if model_id not in provider.models:
            errors.append(f"Unknown model '{model_id}' on provider '{provider_name}'")
            continue

        model_spec = provider.models[model_id]

        # Try each API key
        keys = provider.api_keys.copy()
        if not keys:
            # Try env var convention
            env_name = _PROVIDER_ENV_KEY_MAP.get(provider_name.lower())
            if env_name:
                env_val = os.environ.get(env_name)
                if env_val:
                    keys.append(env_val)

        if not keys:
            errors.append(
                f"Provider '{provider_name}' has no API keys configured. "
                f"Set {_PROVIDER_ENV_KEY_MAP.get(provider_name.lower(), 'API key')} env var "
                f"or add api_keys in ~/.prometheus/llm.yaml"
            )
            continue

        keys_tried = 0
        for key in keys:
            key_short = key[:8] + "..." if len(key) > 8 else key
            if key in excluded_keys:
                continue
            if _is_key_circuit_broken(provider_name, key):
                logger.debug(
                    "Key %s:%s is circuit-broken, skipping", provider_name, key_short
                )  # codeql[py/clear-text-logging-sensitive-data] : key_short is the first 8 chars of the API key, used as a non-reversible identifier
                continue

            keys_tried += 1
            return ResolvedModel(
                provider_name=provider_name,
                model_id=model_id,
                base_url=provider.base_url,
                api_key=key,
                protocol=provider.protocol,
                supports_thinking=model_spec.supports_thinking,
                extra_headers=provider.extra_headers,
                tier=model_spec.tier,
            )

        if keys_tried == 0:
            errors.append(
                f"Provider '{provider_name}': all {len(keys)} keys circuit-broken or excluded"
            )

    raise ModelResolutionError(
        f"Cannot resolve model for tier {tier.value}. Errors:\n"
        + "\n".join(f"  - {e}" for e in errors)
    )


def report_key_failure(resolved: ResolvedModel) -> None:
    """Call when an API call fails with the resolved model's key.

    Records the failure for circuit breaking. The caller should re-resolve
    to get a different key/provider.
    """
    _record_key_failure(resolved.provider_name, resolved.api_key)


# ---------------------------------------------------------------------------
# Scan mode → tier mapping
# ---------------------------------------------------------------------------


def resolve_tier(*, is_child: bool = False) -> Tier:
    """Return the model tier for the current scan.

    Prometheus runs a single scan mode (deep, exhaustive). The root
    agent always uses HARD; child agents always use SIMPLE because they
    do narrow, well-scoped tasks.
    """
    if is_child:
        return Tier.SIMPLE
    return Tier.HARD


# ---------------------------------------------------------------------------
# SDK configuration
# ---------------------------------------------------------------------------


def apply_model_to_sdk(resolved: ResolvedModel) -> None:
    """Configure the OpenAI Agents SDK with the resolved model.

    Sets env vars the SDK reads at client-construction time so
    MultiProvider picks up the correct base_url and API key.
    """
    from agents import set_default_openai_api, set_default_openai_key, set_tracing_disabled

    # Wipe any stale env vars
    for var in _OPENAI_CLIENT_ENV_VARS:
        os.environ.pop(var, None)

    set_tracing_disabled(True)
    set_default_openai_api("chat_completions")
    set_default_openai_key(resolved.api_key, use_for_tracing=False)

    os.environ["OPENAI_BASE_URL"] = resolved.base_url
    os.environ["OPENAI_API_BASE"] = resolved.base_url
    os.environ["LLM_API_BASE"] = resolved.base_url
    os.environ["OPENAI_API_KEY"] = resolved.api_key

    # Extra headers for the provider (e.g., X-HackerOne-Handle for Nous)
    if resolved.extra_headers:
        # The SDK reads HTTP headers from OPENAI_EXTRA_HEADERS as JSON
        import json

        os.environ["OPENAI_EXTRA_HEADERS"] = json.dumps(resolved.extra_headers)

    logger.info(
        "LLM routing: provider=%s model=%s base_url=%s tier=%s thinking=%s",
        resolved.provider_name,
        resolved.model_id,
        resolved.base_url,
        resolved.tier.value,
        resolved.supports_thinking,
    )


# ---------------------------------------------------------------------------
# Tool choice fix for models that don't support it with thinking
# ---------------------------------------------------------------------------

# Models known to reject tool_choice when thinking is active.
# Includes proxy providers (openrouter) because OpenRouter can route
# to DeepSeek or other upstreams that reject tool_choice with thinking,
# and we don't know the upstream at call time.  Phase 3C extends the set
# with the model ids seen in the audit (e.g. custom proxy models whose
# upstream gateway rejects ``tool_choice`` while thinking is active).
_THINKING_NO_TOOL_CHOICE_PROVIDERS: set[str] = {
    "deepseek",
    "openrouter",
    "minimax",
    "minimax-oauth",
    "grok",
    "xai",
}


def should_set_tool_choice(provider_name: str, supports_thinking: bool) -> bool:
    """Return False when tool_choice would cause an API error.

    DeepSeek with thinking mode rejects any tool_choice parameter.
    Other providers with thinking may have the same issue.
    """
    if supports_thinking and provider_name.lower() in _THINKING_NO_TOOL_CHOICE_PROVIDERS:
        return False
    return True


# ---------------------------------------------------------------------------
# .env loading (migration from Hermes)
# ---------------------------------------------------------------------------


def _load_dotenv(path: Path) -> None:
    """Load a .env file into os.environ, skipping already-set vars."""
    if not path.is_file():
        return
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                val = value.strip().strip('"').strip("'")
                if val and val != "***":
                    os.environ[key] = val
    except Exception:
        logger.debug("failed to load env vars, ignoring", exc_info=True)


def _load_all_dotenv() -> None:
    """Load Prometheus .env into os.environ."""
    prom_env = Path.home() / ".prometheus" / ".env"
    _load_dotenv(prom_env)


# ---------------------------------------------------------------------------
# Singleton config (loaded once, refreshed on demand)
# ---------------------------------------------------------------------------

_config: LlmConfig | None = None


def get_config(reload: bool = False) -> LlmConfig:
    """Get the current LLM config, loading from disk if needed."""
    global _config
    if _config is None or reload:
        _load_all_dotenv()  # ensure env vars are loaded
        _config = load_llm_config()
    return _config
