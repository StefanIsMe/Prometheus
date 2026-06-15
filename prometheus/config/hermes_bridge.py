"""Bridge Prometheus model routing to the active Hermes profile.

Prometheus does not own default LLM routing. Hermes is the source of truth.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import set_default_openai_api, set_default_openai_key, set_tracing_disabled

logger = logging.getLogger(__name__)


# Env vars that the OpenAI Agents SDK reads at client-construction time.
# We MUST clear any pre-existing values from the shell before applying our
# resolved routing, otherwise stale entries (e.g. an old 127.0.0.1:1337
# gateway URL) survive and 404 every request even after the bridge has
# resolved the real Hermes model.
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


# Provider-name fragments that signal an Anthropic-protocol endpoint rather
# than an OpenAI Chat-Completions endpoint. When the resolved base_url or
# model provider matches one of these, the OpenAI Agents SDK Chat-
# Completions client cannot talk to it (returns 404). Callers must use
# Anthropic-protocol-aware code paths instead.
#
# Note: ``minimax.io`` is NOT in this list. The MiniMax Portal at
# api.minimax.io exposes BOTH an Anthropic Messages path (/anthropic) and
# an OpenAI Chat-Completions path (/v1/chat/completions). The bridge
# detects which path the active profile's base_url actually targets and
# routes accordingly. Marking the whole provider Anthropic-only here
# would force a needless fallback to a lower-quality model.
_ANTHROPIC_PROTOCOL_MARKERS = (
    "/anthropic",
    "anthropic.com",
)


# Provider-specific base_url overrides. Some providers expose multiple
# protocols on the same host (e.g. MiniMax Portal serves Anthropic at
# /anthropic and OpenAI Chat-Completions at /v1). When the active profile
# points at the Anthropic path but the user wants Prometheus to use the
# OpenAI Chat-Completions endpoint, this map supplies the override.
_OPENAI_COMPATIBLE_BASE_URL_OVERRIDES: dict[str, str] = {
    "minimax-oauth": "https://api.minimax.io/v1",
    "minimax": "https://api.minimax.io/v1",
}


def _base_url_uses_anthropic_protocol(base_url: str | None, provider: str | None) -> bool:
    """True when the resolved gateway speaks the Anthropic Messages API,
    not OpenAI Chat Completions. The OpenAI Agents SDK MultiProvider can
    only hit OpenAI-style /v1/chat/completions endpoints."""
    haystack = " ".join(filter(None, (base_url or "", provider or ""))).lower()
    return any(marker in haystack for marker in _ANTHROPIC_PROTOCOL_MARKERS)


def _resolve_openai_compatible_base_url(base_url: str | None, provider: str | None) -> str | None:
    """Return a base_url that is guaranteed to speak OpenAI Chat-Completions.

    If the active profile's base_url is Anthropic-protocol but the provider
    also exposes an OpenAI Chat-Completions endpoint (e.g. MiniMax Portal),
    the override is returned. Otherwise the original base_url is returned
    unchanged.
    """
    provider_key = (provider or "").split("/", 1)[0].split(":", 1)[0].lower()
    override = _OPENAI_COMPATIBLE_BASE_URL_OVERRIDES.get(provider_key)
    if override is None:
        return base_url
    if not base_url:
        return override
    # If the user already configured the OpenAI-compat path explicitly, do
    # not rewrite it.
    if _base_url_uses_anthropic_protocol(base_url, provider_key):
        return override
    return base_url


def _clear_openai_client_env() -> None:
    """Remove OpenAI/Agents-SDK env vars so the SDK client picks up the
    bridge's resolved values instead of any shell-leftover ones."""
    for var in _OPENAI_CLIENT_ENV_VARS:
        os.environ.pop(var, None)


def _patch_openai_codex_responses_replay() -> None:
    """Make store=False multi-turn Responses runs work on ChatGPT Codex.

    The Codex Responses backend requires ``store=false``. It also returns
    reasoning output items with ``rs_*`` IDs. The OpenAI Agents SDK replays
    previous output items on the next turn, and Codex rejects those reasoning
    IDs because they were not persisted. Reasoning items are hidden model state,
    not user-visible conversation content, so dropping them preserves the usable
    transcript while avoiding wasted retry loops.
    """
    try:
        from agents.models.openai_responses import OpenAIResponsesModel
    except Exception:
        logger.debug("Could not import OpenAIResponsesModel for Codex replay patch", exc_info=True)
        return

    if getattr(OpenAIResponsesModel, "_prometheus_codex_replay_patch", False):
        return

    original = getattr(
        OpenAIResponsesModel,
        "_remove_openai_responses_api_incompatible_fields",
    )

    def patched(self: Any, list_input: list[Any]) -> list[Any]:
        cleaned = original(self, list_input)
        return [
            item
            for item in cleaned
            if not (isinstance(item, dict) and item.get("type") == "reasoning")
        ]

    setattr(OpenAIResponsesModel, "_remove_openai_responses_api_incompatible_fields", patched)
    setattr(OpenAIResponsesModel, "_prometheus_codex_replay_patch", True)


def _patch_chat_completions_invalid_function_arguments() -> None:
    """Sanitize invalid function-call argument JSON before it leaves for the
    provider.

    The OpenAI Agents SDK passes the model's tool-call ``arguments`` string
    verbatim to the provider. Strict gateways (TokenRouter, certain vLLM
    deployments, OpenAI-compatible proxies) reject the request with HTTP
    400 ``invalid function arguments json string`` (code 2013) when the
    arguments are not parseable JSON — typically because the model was
    cut off mid-stream and produced a truncated string, emitted an
    unterminated literal, or included stray control characters.

    Without this patch the whole scan aborts: the SDK raises
    ``openai.BadRequestError`` out of the streaming handler and the agent
    never gets a turn to recover. We don't try to *recover* the truncated
    JSON (that's lossy and dangerous), we just:

    1. Replace the offending tool call's ``arguments`` with ``"{}"`` so the
       request reaches the provider. The provider's tool-execution layer
       will then dispatch the call to the SDK with no arguments, which the
       tool wrapper reports as a clear "missing required arguments" error
       and returns to the model on the *next* turn.
    2. Inject a synthetic ``function_call_output`` item right after the bad
       tool call, with ``call_id`` matching the original tool call and an
       ``output`` explaining the JSON was invalid. The model sees what
       happened and can correct course in the same turn.

    The patch is idempotent: it only fires when the patch flag is not yet
    set, and it preserves the original ``Converter.items_to_messages`` so
    SDK upgrades don't silently break us.
    """
    try:
        from agents.models.chatcmpl_converter import Converter
    except Exception:
        logger.debug(
            "Could not import agents.models.chatcmpl_converter for invalid-args patch",
            exc_info=True,
        )
        return

    if getattr(Converter, "_prometheus_invalid_args_patch", False):
        return

    original_items_to_messages = Converter.items_to_messages
    original_message_to_output_items = getattr(Converter, "message_to_output_items", None)

    import json as _json
    from typing import Iterable as _Iterable, cast as _cast

    def _is_valid_arguments_json(value: Any) -> bool:
        """Return True when ``value`` is a JSON string that parses to an object/dict.

        Tool arguments must be a JSON object per OpenAI's contract, but a
        surprising number of model mistakes produce strings, lists, or
        numbers in this field. We treat anything non-object as invalid so
        the provider doesn't 400.
        """
        if not isinstance(value, str):
            return False
        stripped = value.strip()
        if not stripped:
            return True  # empty string is treated as {} upstream already
        try:
            parsed = _json.loads(stripped)
        except (ValueError, TypeError):
            return False
        return isinstance(parsed, dict)

    def _extract_arguments(item: Any) -> tuple[str, str | None, str | None, str | None]:
        """Pull ``(arguments, call_id, name, type)`` from a function_call item.

        Returns ``(arguments, call_id, name, type)`` or ``("", None, None, None)``
        if the item is not a function call.
        """
        if isinstance(item, dict):
            if item.get("type") == "function_call":
                return (
                    str(item.get("arguments") or ""),
                    item.get("call_id"),
                    item.get("name"),
                    "function_call",
                )
            return ("", None, None, None)
        # Pydantic model
        if getattr(item, "type", None) == "function_call":
            return (
                str(getattr(item, "arguments", "") or ""),
                getattr(item, "call_id", None),
                getattr(item, "name", None),
                "function_call",
            )
        return ("", None, None, None)

    def _maybe_synthesize_output(
        call_id: str | None,
        name: str | None,
        original_args: str,
        exc: Exception,
    ) -> dict[str, Any] | None:
        if not call_id:
            return None
        snippet = (original_args or "").strip()
        if len(snippet) > 240:
            snippet = snippet[:240] + "…"
        message = (
            f"INVALID_ARGUMENTS_JSON: tool '{name or '<unknown>'}' (call_id={call_id}) "
            f"was produced with arguments that are not a valid JSON object. "
            f"Original arguments were replaced with {{}} to keep the request valid. "
            f"Parser error: {exc}. Original (truncated): {snippet!r}. "
            f"Please retry the call with a complete, well-formed JSON object."
        )
        return {
            "type": "function_call_output",
            "call_id": call_id,
            "output": message,
        }

    def patched_items_to_messages(
        cls,
        items: Any,
        model: str | None = None,
        preserve_thinking_blocks: bool = False,
        preserve_tool_output_all_content: bool = False,
        base_url: str | None = None,
        should_replay_reasoning_content: Any = None,
    ) -> list[Any]:
        # Sanitize the input list in place: when a function_call item has
        # arguments that aren't a valid JSON object, we (a) replace its
        # arguments with "{}", and (b) inject a synthetic function_call_output
        # right after it so the model sees a clear error. The original SDK
        # path runs unchanged on the cleaned list.
        try:
            cleaned: list[Any] = []
            if isinstance(items, str):
                cleaned = [items]
            else:
                for item in items:
                    cleaned.append(item)
                    arguments, call_id, name, kind = _extract_arguments(item)
                    if kind != "function_call":
                        continue
                    if _is_valid_arguments_json(arguments):
                        continue
                    # Capture the parse error in a name that lives at the
                    # function scope, NOT the except block, so the second
                    # invalid item in the same batch doesn't trip an
                    # UnboundLocalError when we re-enter this branch.
                    parse_exc: Exception = _json.JSONDecodeError(
                        "arguments is not a JSON object", arguments or "", 0
                    )
                    logger.warning(
                        "Sanitizing invalid tool-call arguments for call_id=%s tool=%s: %s",
                        call_id,
                        name,
                        parse_exc,
                    )
                    # Mutate the item in place so the original SDK path sees
                    # valid JSON when it walks the assistant message.
                    if isinstance(item, dict):
                        item["arguments"] = "{}"
                    else:
                        # Pydantic model — try attribute assignment first,
                        # fall back to reconstructing the item.
                        try:
                            setattr(item, "arguments", "{}")
                        except Exception:
                            cleaned[-1] = {
                                **{
                                    k: getattr(item, k)
                                    for k in (
                                        "id",
                                        "call_id",
                                        "name",
                                        "type",
                                        "provider_data",
                                        "namespace",
                                        "status",
                                    )
                                    if hasattr(item, k) and k != "arguments"
                                },
                                "type": "function_call",
                                "call_id": call_id,
                                "name": name,
                                "arguments": "{}",
                            }
                    synthesized = _maybe_synthesize_output(call_id, name, arguments, parse_exc)
                    if synthesized is not None:
                        cleaned.append(synthesized)
            return original_items_to_messages.__func__(
                cls,
                cleaned,
                model=model,
                preserve_thinking_blocks=preserve_thinking_blocks,
                preserve_tool_output_all_content=preserve_tool_output_all_content,
                base_url=base_url,
                should_replay_reasoning_content=should_replay_reasoning_content,
            )
        except Exception:
            # Never let the patch itself crash a scan. Fall back to the
            # unmodified SDK behavior.
            logger.debug(
                "Invalid-args sanitizer fell back to unmodified Converter.items_to_messages",
                exc_info=True,
            )
            return original_items_to_messages.__func__(
                cls,
                items,
                model=model,
                preserve_thinking_blocks=preserve_thinking_blocks,
                preserve_tool_output_all_content=preserve_tool_output_all_content,
                base_url=base_url,
                should_replay_reasoning_content=should_replay_reasoning_content,
            )

    # Bind as a classmethod.
    Converter.items_to_messages = classmethod(patched_items_to_messages)  # type: ignore[assignment]
    setattr(Converter, "_prometheus_invalid_args_patch", True)
    setattr(Converter, "_prometheus_invalid_args_original", original_items_to_messages)


@dataclass(frozen=True)
class HermesModelResolution:
    provider: str
    model: str
    base_url: str | None
    api_key_env_name: str | None
    api_key_present: bool
    source_profile: str | None


class HermesModelResolutionError(RuntimeError):
    """Raised when the active Hermes model cannot be resolved."""


_PROVIDER_API_KEY_ENV: dict[str, str | None] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "openai-codex": "OPENAI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "nous": "NOUS_API_KEY",
    "novita": "NOVITA_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
    "bedrock": None,
    "vertex": None,
    "ollama": None,
    "local": None,
}


def _load_hermes_dotenv() -> None:
    """Load ``~/.hermes/.env`` into os.environ so API keys from the
    Hermes env file are visible to Prometheus at runtime.

    Only sets variables that are not already present in the environment
    (dotenv ``override=False`` semantics).  Silently returns if the file
    does not exist or is unreadable.
    """
    env_path = Path.home() / ".hermes" / ".env"
    if not env_path.is_file():
        return
    try:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip('"').strip("'")
    except Exception:
        pass


def _ensure_hermes_import_path() -> None:
    hermes_agent = Path.home() / ".hermes" / "hermes-agent"
    if hermes_agent.exists():
        path = str(hermes_agent)
        if path not in sys.path:
            sys.path.insert(0, path)


def _load_hermes_config() -> dict[str, Any]:
    _ensure_hermes_import_path()
    try:
        from hermes_cli.config import load_config
    except Exception as exc:  # pragma: no cover - exercised by integration failure path
        raise HermesModelResolutionError(
            "Cannot import Hermes config loader hermes_cli.config.load_config"
        ) from exc

    try:
        config = load_config()
    except Exception as exc:  # pragma: no cover - depends on local Hermes state
        raise HermesModelResolutionError("Hermes config loader failed") from exc

    if not isinstance(config, dict):
        raise HermesModelResolutionError(
            f"Hermes load_config() returned {type(config).__name__}, expected dict"
        )
    return config


def _api_key_env_for_provider(provider: str) -> str | None:
    provider_key = provider.split("/", 1)[0].split(":", 1)[0].lower()
    if provider_key in _PROVIDER_API_KEY_ENV:
        return _PROVIDER_API_KEY_ENV[provider_key]
    return f"{provider_key.upper().replace('-', '_')}_API_KEY"


def resolve_active_hermes_model() -> HermesModelResolution:
    """Resolve the active Hermes model from the official Hermes config loader.

    Failure is loud. There is no Prometheus owned fallback.
    """
    config = _load_hermes_config()
    model_config = config.get("model")
    if not isinstance(model_config, dict):
        raise HermesModelResolutionError("Hermes config is missing model section")

    provider = str(model_config.get("provider") or "").strip()
    model = str(model_config.get("default") or model_config.get("model") or "").strip()
    base_url_raw = model_config.get("base_url")
    base_url = str(base_url_raw).strip() if base_url_raw else None

    if not provider:
        raise HermesModelResolutionError("Hermes model.provider is missing")
    if not model:
        raise HermesModelResolutionError("Hermes model.default is missing")

    api_key_env_name = _api_key_env_for_provider(provider)
    api_key_present = bool(api_key_env_name and os.environ.get(api_key_env_name))
    source_profile = (
        os.environ.get("HERMES_PROFILE")
        or os.environ.get("HERMES_ACTIVE_PROFILE")
        or str(config.get("profile") or "default")
    )

    return HermesModelResolution(
        provider=provider,
        model=model,
        base_url=base_url,
        api_key_env_name=api_key_env_name,
        api_key_present=api_key_present,
        source_profile=source_profile,
    )


def _api_key_for_resolution(resolution: HermesModelResolution) -> str:
    if resolution.api_key_env_name:
        value = os.environ.get(resolution.api_key_env_name)
        if value:
            return value

    # OpenAI Codex stores OAuth credentials in Hermes' Codex token store and
    # credential pool, not as top-level agent_key/access_token fields. Use the
    # official Hermes runtime resolver so Prometheus follows the same refresh
    # path as Hermes instead of treating a valid login as expired.
    if resolution.provider == "openai-codex":
        try:
            _ensure_hermes_import_path()
            from hermes_cli.auth import resolve_codex_runtime_credentials

            creds = resolve_codex_runtime_credentials()
        except Exception as exc:
            raise HermesModelResolutionError(
                "Hermes provider 'openai-codex' has no usable Codex OAuth "
                "credential. Run `hermes auth add openai-codex` if refresh fails."
            ) from exc
        api_key = creds.get("api_key") if isinstance(creds, dict) else None
        if isinstance(api_key, str) and api_key.strip():
            return api_key.strip()
        raise HermesModelResolutionError(
            "Hermes provider 'openai-codex' resolved without an api_key. "
            "Run `hermes auth add openai-codex`."
        )

    # Fall back to the active Hermes profile's auth.json OAuth credentials.
    # Provider APIs like Nous Portal and MiniMax use short-lived JWTs
    # stored in ``<hermes_home>/auth.json``; env vars alone won't have
    # them. The helper already falls back to the global-root auth store
    # when the profile has no per-provider entry, but profile state
    # shadows the global store when it does exist — even with expired
    # tokens. Detect that and re-query global-only so a freshly
    # authenticated global session is still usable.
    if resolution.provider:
        usable = _first_usable_token(_read_provider_auth(resolution.provider))
        if usable is not None:
            return usable

        global_state = _read_global_provider_auth(resolution.provider)
        if global_state is not None:
            usable = _first_usable_token(global_state)
            if usable is not None:
                return usable

        # If we got here, the profile's auth state exists but is expired,
        # and no fresh global state either. Tell the user to re-auth.
        raise HermesModelResolutionError(
            f"Hermes provider {resolution.provider!r} has no usable OAuth "
            f"token in the active profile's auth.json. The cached "
            f"agent_key/access_token are expired. Run "
            f"`hermes auth login {resolution.provider}` to refresh."
        )

    # OpenAI-compatible custom gateways often only require a non-empty key.
    # This is not a model fallback. Routing still comes only from Hermes.
    if resolution.base_url:
        return "no-key-required"

    raise HermesModelResolutionError(
        f"Hermes provider {resolution.provider!r} requires {resolution.api_key_env_name or 'an API key'}, but it is not set"
    )


def _token_is_expired(state: dict[str, Any], token_field: str, provider: str) -> bool:
    """Best-effort expiry check. Returns True if the token is clearly stale,
    False if it's clearly fresh, and False if we can't tell."""
    try:
        from datetime import datetime, timezone

        expiry_field = "agent_key_expires_at" if token_field == "agent_key" else "expires_at"
        expiry = state.get(expiry_field)
        if not isinstance(expiry, str) or not expiry.strip():
            return False  # unknown expiry, assume usable
        normalized = expiry.replace("Z", "+00:00")
        expires_at = datetime.fromisoformat(normalized)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expires_at
    except Exception:
        return False


def _read_provider_auth(provider: str) -> dict[str, Any] | None:
    """Read the active Hermes profile's auth state for ``provider``."""
    try:
        from hermes_cli.auth import get_provider_auth_state

        state = get_provider_auth_state(provider)
    except Exception:
        return None
    return state if isinstance(state, dict) else None


def _read_global_provider_auth(provider: str) -> dict[str, Any] | None:
    """Read the global-root ``~/.hermes/auth.json`` for ``provider``,
    bypassing the active profile. Returns None in classic (non-profile) mode."""
    try:
        from hermes_cli.auth import _load_global_auth_store, _load_provider_state

        global_store = _load_global_auth_store()
    except Exception:
        return None
    if not isinstance(global_store, dict):
        return None
    state = _load_provider_state(global_store, provider)
    return state if isinstance(state, dict) else None


def _first_usable_token(state: dict[str, Any] | None) -> str | None:
    """Return the first non-expired credential in ``state``, or None."""
    if not isinstance(state, dict):
        return None
    for key_name in ("agent_key", "access_token", "runtime_api_key"):
        token = state.get(key_name)
        if isinstance(token, str) and token.strip():
            if not _token_is_expired(state, key_name, ""):
                return token.strip()
    return None


def _resolve_fallback_openai_compatible_model() -> "HermesModelResolution | None":
    """Find a Hermes profile whose model gateway is OpenAI Chat-Completions
    compatible, for use when the active profile points at an Anthropic
    Messages API endpoint that the OpenAI Agents SDK cannot talk to.

    Search order: explicit ``prometheus`` and ``security`` profiles (the
    canonical names operators tend to use for Prometheus/Security work),
    then any profile under ``~/.hermes/profiles/`` that exposes a
    non-Anthropic ``base_url``. Returns the first usable resolution.

    Reads each profile's ``config.yaml`` directly so we don't depend on
    the Hermes ``_LOAD_CONFIG_CACHE`` (which is keyed by absolute config
    path and would otherwise return the same cached default config for
    every profile in a single process).
    """
    import yaml  # PyYAML is a Hermes runtime dependency

    profiles_root = Path.home() / ".hermes" / "profiles"
    if not profiles_root.is_dir():
        return None

    preferred = ("prometheus", "security")
    candidates: list[str] = []
    for name in preferred:
        if (profiles_root / name).is_dir():
            candidates.append(name)
    try:
        for entry in sorted(profiles_root.iterdir()):
            if entry.is_dir() and entry.name not in candidates:
                candidates.append(entry.name)
    except OSError:
        pass

    for name in candidates:
        config_path = profiles_root / name / "config.yaml"
        if not config_path.is_file():
            continue
        try:
            with open(config_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(raw, dict):
            continue
        model_cfg = raw.get("model")
        if not isinstance(model_cfg, dict):
            continue
        provider = str(model_cfg.get("provider") or "").strip()
        model = str(model_cfg.get("default") or model_cfg.get("model") or "").strip()
        if not provider or not model:
            continue
        base_url_raw = model_cfg.get("base_url")
        base_url = str(base_url_raw).strip() if base_url_raw else None
        if _base_url_uses_anthropic_protocol(base_url, provider):
            continue
        api_key_env = _api_key_env_for_provider(provider)
        api_key_present = bool(api_key_env and os.environ.get(api_key_env))
        return HermesModelResolution(
            provider=provider,
            model=model,
            base_url=base_url,
            api_key_env_name=api_key_env,
            api_key_present=api_key_present,
            source_profile=name,
        )
    return None


def apply_hermes_model_defaults(settings: Any | None = None) -> HermesModelResolution:
    """Apply active Hermes model routing to the OpenAI Agents SDK defaults.

    The optional settings object is mutated for compatibility with existing
    Prometheus call sites that read settings.llm.model/api_base/api_key.

    Stale OpenAI SDK env vars from the shell are wiped first so the SDK
    client constructor doesn't see conflicting base URLs. If the resolved
    base_url speaks the Anthropic Messages API rather than OpenAI Chat
    Completions, we abort with a clear error — the OpenAI Agents SDK
    cannot talk to that endpoint.
    """
    _load_hermes_dotenv()
    resolution = resolve_active_hermes_model()
    api_key = _api_key_for_resolution(resolution)

    # Some providers expose both Anthropic and OpenAI Chat-Completions
    # endpoints on the same host (e.g. MiniMax Portal at api.minimax.io).
    # If the active profile points at the Anthropic path, rewrite to the
    # OpenAI Chat-Completions path so the OpenAI Agents SDK can talk to
    # the SAME provider/model the user is using with Hermes — no quality
    # downgrade, no fallback profile required.
    original_base_url = resolution.base_url
    rewritten_base_url = _resolve_openai_compatible_base_url(
        resolution.base_url, resolution.provider
    )
    if rewritten_base_url != original_base_url:
        logger.warning(
            "Active Hermes base_url %s uses Anthropic protocol for provider %s; "
            "rewriting to OpenAI Chat-Completions endpoint %s for Prometheus.",
            original_base_url,
            resolution.provider,
            rewritten_base_url,
        )
        resolution = HermesModelResolution(
            provider=resolution.provider,
            model=resolution.model,
            base_url=rewritten_base_url,
            api_key_env_name=resolution.api_key_env_name,
            api_key_present=resolution.api_key_present,
            source_profile=resolution.source_profile,
        )

    if _base_url_uses_anthropic_protocol(resolution.base_url, resolution.provider):
        # The active profile's model is Anthropic-protocol. Prometheus'
        # OpenAI Agents SDK can't talk to that. Auto-fall back to a
        # profile whose gateway speaks OpenAI Chat-Completions so the
        # user can run prometheus without remembering to switch
        # profiles. We try ``prometheus`` itself first, then ``security``,
        # then scan the profiles directory for any non-Anthropic config.
        fallback = _resolve_fallback_openai_compatible_model()
        if fallback is None:
            raise HermesModelResolutionError(
                f"Active Hermes model uses an Anthropic-protocol endpoint "
                f"(provider={resolution.provider!r}, base_url={resolution.base_url!r}, "
                f"model={resolution.model!r}). The OpenAI Agents SDK in Prometheus "
                f"only supports OpenAI Chat-Completions endpoints. Configure a "
                f"Hermes profile that resolves to an OpenAI-style gateway (e.g. "
                f"provider=nous with base_url=https://inference-api.nousresearch.com/v1) "
                f"and either switch the active profile or set "
                f"HERMES_HOME to that profile's directory."
            )
        resolution = fallback
        api_key = _api_key_for_resolution(resolution)
        logger.warning(
            "Active Hermes profile uses an Anthropic-protocol gateway; "
            "Prometheus auto-fell-back to profile=%s provider=%s model=%s "
            "because the OpenAI Agents SDK only supports OpenAI Chat-Completions.",
            resolution.source_profile,
            resolution.provider,
            resolution.model,
        )

    _clear_openai_client_env()

    sdk_api = "responses" if resolution.provider == "openai-codex" else "chat_completions"
    if resolution.provider == "openai-codex":
        _patch_openai_codex_responses_replay()
    if sdk_api == "chat_completions":
        # Sanitize invalid function-call JSON for any Chat-Completions
        # provider (TokenRouter in particular returns 400 code 2013 on
        # unparseable arguments; see the patch docstring for the full
        # recovery model).
        _patch_chat_completions_invalid_function_arguments()
    # Prometheus uses Hermes OAuth/runtime credentials for model routing. The
    # OpenAI Agents SDK tracing exporter requires a platform secret key and will
    # repeatedly POST /v1/traces/ingest with the OAuth token if tracing remains
    # enabled. That is noisy, wasteful, and fails with 401. Local Prometheus
    # artifacts are the source of truth for scan observability.
    set_tracing_disabled(True)
    set_default_openai_api(sdk_api)
    set_default_openai_key(api_key, use_for_tracing=False)

    if resolution.base_url:
        os.environ["OPENAI_BASE_URL"] = resolution.base_url
        os.environ["OPENAI_API_BASE"] = resolution.base_url
        os.environ["LLM_API_BASE"] = resolution.base_url
    os.environ["OPENAI_API_KEY"] = api_key

    if settings is not None and getattr(settings, "llm", None) is not None:
        settings.llm.model = resolution.model
        settings.llm.api_base = resolution.base_url
        settings.llm.api_key = api_key
        # ``use_hermes_model`` was a legacy field on LlmSettings that
        # has since been removed; the new Prometheus routing owns the
        # model selection via prometheus.config.llm_config. Setting
        # it would raise ``ValueError: object has no field`` on the
        # current Settings class, so we omit the assignment and rely
        # on the env-var + ResolvedModel path for the rest of the
        # call sites.

    logger.info(
        "Hermes model resolved: provider=%s model=%s base_url=%s profile=%s api_key_env=%s present=%s",
        resolution.provider,
        resolution.model,
        resolution.base_url or "<none>",
        resolution.source_profile or "<unknown>",
        resolution.api_key_env_name or "<none>",
        resolution.api_key_present,
    )
    return resolution
