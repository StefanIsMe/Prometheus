"""Settings loader, override switch, and disk persistence."""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import AliasChoices, BaseModel

from prometheus.config.settings import Settings


if TYPE_CHECKING:
    from pydantic.fields import FieldInfo


logger = logging.getLogger(__name__)


_DEFAULT_PATH: Path = Path.home() / ".prometheus" / "cli-config.json"
_override: Path | None = None
_cached: Settings | None = None

# Prometheus JSON config is not an LLM routing source of truth.
# These legacy keys may still exist on disk, but Hermes owns them now.
_LLM_ROUTING_ALIASES = {
    "PROMETHEUS_LLM",
    "PROMETHEUS_USE_HERMES_MODEL",
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
}


def load_settings() -> Settings:
    """Resolve settings from env + JSON file + defaults. Memoized.

    Precedence: env vars win, then the JSON file, then field defaults.
    """
    global _cached  # noqa: PLW0603
    if _cached is None:
        source_path = _override or _DEFAULT_PATH
        init_kwargs: dict[str, Any] = _read_json_overrides(source_path)
        _cached = Settings(**init_kwargs)
        logger.debug(
            "load_settings: resolved (override=%s, file_used=%s, json_keys=%d)",
            _override is not None,
            source_path.exists(),
            sum(len(v) for v in init_kwargs.values()),
        )
    return _cached


def apply_config_override(path: Path) -> None:
    """Switch the JSON source to ``path`` and invalidate the cache."""
    global _override, _cached  # noqa: PLW0603
    _override = path
    _cached = None
    logger.info("config override applied: %s", path)


def persist_current() -> None:
    """Write currently-set env vars to the active config file (0o600).

    Merges with existing file contents so keys that aren't in the
    current environment are preserved (avoids wiping prometheus_LLM /
    LLM_API_KEY when running without the prometheus-ogw wrapper).
    """
    s = load_settings()
    target = _override or _DEFAULT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    # Read existing config to preserve keys not in current env
    existing_env: dict[str, str] = {}
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                raw = existing.get("env", {})
                if isinstance(raw, dict):
                    existing_env = {str(k).upper(): str(v) for k, v in raw.items()}
        except (json.JSONDecodeError, OSError):
            logger.debug("could not load existing settings env, starting empty", exc_info=True)

    env_block: dict[str, str] = dict(existing_env)  # start with existing
    for sub_name in s.model_fields:
        sub_model = getattr(s, sub_name)
        if not isinstance(sub_model, BaseModel):
            continue
        for finfo in type(sub_model).model_fields.values():
            for alias in _aliases_for(finfo):
                value = os.environ.get(alias.upper())
                if value:
                    if alias.upper() in _LLM_ROUTING_ALIASES:
                        continue
                    env_block[alias.upper()] = value
                    break

    target.write_text(json.dumps({"env": env_block}, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        target.chmod(0o600)


def _aliases_for(finfo: FieldInfo) -> list[str]:
    """Collect every env-var name that should populate ``finfo``."""
    aliases: list[str] = []
    if finfo.alias:
        aliases.append(finfo.alias)
    va = finfo.validation_alias
    if isinstance(va, AliasChoices):
        aliases.extend(c for c in va.choices if isinstance(c, str))
    elif isinstance(va, str):
        aliases.append(va)
    return aliases


def _read_json_overrides(path: Path) -> dict[str, dict[str, Any]]:
    """Read ``{"env": {...}}`` from ``path`` and remap to nested kwargs.

    Only includes keys whose env var is NOT already set, so env always
    wins over the persisted file.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    env_block = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env_block, dict):
        return {}

    env_block_upper = {str(k).upper(): v for k, v in env_block.items()}

    nested: dict[str, dict[str, Any]] = {}
    for sub_name, sub_finfo in Settings.model_fields.items():
        sub_cls = sub_finfo.annotation
        if not (isinstance(sub_cls, type) and issubclass(sub_cls, BaseModel)):
            continue
        sub_data: dict[str, Any] = {}
        for fname, finfo in sub_cls.model_fields.items():
            for alias in _aliases_for(finfo):
                key = alias.upper()
                if key in os.environ:
                    break  # env wins; skip JSON for this field
                if key in _LLM_ROUTING_ALIASES:
                    continue
                if key in env_block_upper:
                    sub_data[fname] = env_block_upper[key]
                    break
        if sub_data:
            nested[sub_name] = sub_data
    return nested
