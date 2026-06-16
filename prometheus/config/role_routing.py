"""Per-role model routing — the runner resolves the model per stage.

This is the runtime side of the ``prometheus/config/role_routing.yaml``
config file. The Hermes bridge provides the model catalog; this
module decides which model to ask for at each stage.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


_DEFAULT_PATH = Path(__file__).resolve().parent / "role_routing.yaml"


_TIER_ALIASES = {
    "haiku": "cheap",
    "sonnet": "standard",
    "opus": "strong",
}


def _normalize_tier(tier: str | None) -> str:
    if not tier:
        return "standard"
    t = str(tier).strip().lower()
    t = _TIER_ALIASES.get(t, t)
    if t not in {"cheap", "standard", "strong"}:
        return "standard"
    return t


@lru_cache(maxsize=1)
def _load_routing(path: str | None = None) -> dict[str, str]:
    """Load the routing YAML; fall back to defaults if PyYAML is missing."""
    p = Path(path or os.environ.get("PROMETHEUS_ROLE_ROUTING") or _DEFAULT_PATH)
    if not p.is_file():
        return _default_routing()
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not available; using default routing")
        return _default_routing()
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("role_routing.yaml unreadable: %s; using defaults", exc)
        return _default_routing()
    if not isinstance(raw, dict):
        return _default_routing()
    out: dict[str, str] = {}
    defaults = raw.get("defaults") if isinstance(raw.get("defaults"), dict) else None
    if defaults:
        for k, v in defaults.items():
            if isinstance(k, str) and isinstance(v, str):
                out[k.strip()] = _normalize_tier(v)
    # Top-level keys override the defaults block.
    for k, v in raw.items():
        if k == "defaults":
            continue
        if isinstance(k, str) and isinstance(v, str):
            out[k.strip()] = _normalize_tier(v)
    if not out:
        return _default_routing()
    return out


def _default_routing() -> dict[str, str]:
    return {
        "s1_scope": "cheap",
        "s2_threatmodel": "cheap",
        "s3_recon": "cheap",
        "s4_deepdive": "standard",
        "s5_prefilter": "cheap",
        "s6_verify": "strong",
        "s7_dedup": "cheap",
        "s8_report": "standard",
        "s9_sarif": "cheap",
    }


@dataclass(frozen=True)
class StageRouting:
    stage: str
    tier: str

    def to_dict(self) -> dict[str, str]:
        return {"stage": self.stage, "tier": self.tier}


def routing_for(stage: str) -> StageRouting:
    """Return the routing decision for ``stage``.

    Unknown stages fall back to ``standard``. The Hermes bridge is
    expected to translate the tier into a concrete model ID.
    """
    table = _load_routing()
    tier = table.get(stage, "standard")
    return StageRouting(stage=stage, tier=tier)


def all_routings() -> list[StageRouting]:
    """Return the full routing table (for tests + diagnostics)."""
    table = _load_routing()
    return [StageRouting(stage=k, tier=v) for k, v in sorted(table.items())]


def clear_cache() -> None:
    """Reset the YAML load cache (tests + hot-reload)."""
    _load_routing.cache_clear()


__all__ = [
    "StageRouting",
    "all_routings",
    "clear_cache",
    "routing_for",
]
