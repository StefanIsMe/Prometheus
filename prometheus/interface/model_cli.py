"""Prometheus model — manage LLM providers and models.

Subcommands:
  list                        Show current providers, models, and routing
  set <provider/model>        Set active model across all routing tiers
  add <name> <base_url>       Add a custom OpenAI-compatible endpoint
  remove <name>               Remove a provider/endpoint

Config lives at ~/.prometheus/llm.yaml.
API keys should be set as env vars in ~/.prometheus/.env.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path.home() / ".prometheus" / "llm.yaml"
ENV_PATH = Path.home() / ".prometheus" / ".env"


def _load() -> dict[str, Any]:
    """Load the YAML config."""
    if not CONFIG_PATH.is_file():
        return {"providers": {}, "routing": {}, "defaults": {"tier": "medium"}}
    raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
    raw.setdefault("providers", {})
    raw.setdefault("routing", {})
    raw.setdefault("defaults", {"tier": "medium"})
    return raw


def _save(data: dict[str, Any]) -> None:
    """Write the YAML config back to disk."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    print(f"  Written: {CONFIG_PATH}")


def _resolve_env_name(name: str) -> str:
    """Derive the env var name for a provider."""
    base = name.upper().replace("-", "_")
    return f"{base}_API_KEY"


def _get_key_from_env(name: str) -> str | None:
    """Try to find an API key for the provider name from .env or os.environ."""
    env_name = _resolve_env_name(name)
    # Check .prometheus/.env first
    if ENV_PATH.is_file():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key.strip() == env_name:
                val = val.strip().strip("\"'")
                if val and val != "***":
                    return val
    # Fall back to process environment
    return os.environ.get(env_name)


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------


def _cmd_list() -> None:
    data = _load()
    providers = data.get("providers", {})
    routing = data.get("routing", {})
    defaults = data.get("defaults", {})

    if not providers:
        print("No providers configured.")
        print(f"  Add one: prometheus model add <name> <base_url>")
        print(f"  Or set : prometheus model set <provider/model>")
        return

    # Active model detection: first candidate in medium tier
    active: str | None = None
    medium = routing.get("medium", {})
    models_list = medium if isinstance(medium, list) else medium.get("models", [])
    if models_list:
        active = (
            models_list[0]
            if isinstance(models_list[0], str)
            else f"{models_list[0].get('provider', '?')}/{models_list[0].get('model', '?')}"
        )

    if active:
        print(f"Active: {active}\n")
    else:
        print("No active model set.\n")

    # List providers
    print("Providers:")
    for pname, pdata in providers.items():
        base_url = pdata.get("base_url", "?")
        env_var = _resolve_env_name(pname)
        has_key = "yes" if _get_key_from_env(pname) else "no"
        print(f"  {pname}")
        print(f"    base_url: {base_url}")
        print(f"    api_key:  {env_var} ({has_key})")

        models = pdata.get("models", {})
        if models:
            for mid, mdata in models.items():
                if isinstance(mdata, dict):
                    tier = mdata.get("tier", "?")
                    ctx = mdata.get("max_tokens", "?")
                    print(f"    model: {mid}  (tier={tier}, max_tokens={ctx})")
                else:
                    print(f"    model: {mid}  ({mdata})")
        else:
            print(f"    model: (none)")

    print()

    # List routing
    print("Routing:")
    if routing:
        for tier_name in ("simple", "medium", "hard"):
            tier_data = routing.get(tier_name)
            if not tier_data:
                continue
            models_entry = tier_data if isinstance(tier_data, list) else tier_data.get("models", [])
            models_str = ", ".join(str(m) for m in models_entry) if models_entry else "(none)"
            print(f"  {tier_name}: {models_str}")
    else:
        print("  (auto-resolved from model tiers)")

    print()
    print(f"Default tier: {defaults.get('tier', 'medium')}")


# ---------------------------------------------------------------------------
# Subcommand: set
# ---------------------------------------------------------------------------


def _cmd_set(model_ref: str) -> None:
    """Set the active model across all routing tiers.

    Model ref can be:
      - provider/model   (e.g. openrouter/nvidia/...)
      - model_id         (looked up from existing providers)
    """
    data = _load()
    providers = data.get("providers", {})

    # Parse ref — provider is the first segment before the known provider name,
    # model is everything after. Handle nested '/' in model IDs.
    if "/" in model_ref:
        # Try each prefix as provider name
        parts = model_ref.split("/")
        for split_idx in range(1, len(parts)):
            candidate_provider = "/".join(parts[:split_idx])
            if candidate_provider in providers:
                provider = candidate_provider
                model = "/".join(parts[split_idx:])
                break
        else:
            # No known provider matched; fall back to first-segment heuristic
            provider = parts[0]
            model = "/".join(parts[1:])
    else:
        # Search all providers for a matching model_id
        found = []
        for pname, pdata in providers.items():
            if model_ref in (pdata.get("models", {}) or {}):
                found.append((pname, model_ref))
            # Also check: model names might be stored differently
        if len(found) == 0:
            print(f"Error: model '{model_ref}' not found in any provider.")
            print(f"  List available: prometheus model list")
            sys.exit(1)
        elif len(found) > 1:
            print(f"Error: model '{model_ref}' found in multiple providers:")
            for p, m in found:
                print(f"  {p}/{m}")
            print("  Use 'provider/model' format to disambiguate.")
            sys.exit(1)
        provider, model = found[0]

    # Verify the model exists on the provider
    if provider not in providers:
        print(f"Error: provider '{provider}' not found in config.")
        print(f"  Add first: prometheus model add {provider} <base_url>")
        sys.exit(1)

    pdata = providers[provider]
    pmodels = pdata.get("models", {}) or {}
    if model not in pmodels:
        # Auto-register unknown models instead of rejecting
        pmodels[model] = {"tier": "hard", "max_tokens": 65536}

    # Update routing — set this model for all three tiers
    routing = data.setdefault("routing", {})
    for tier_name in ("simple", "medium", "hard"):
        # Preserve existing structure; just replace the candidate list
        existing = routing.get(tier_name)
        if isinstance(existing, dict):
            existing["models"] = [f"{provider}/{model}"]
        else:
            routing[tier_name] = {"models": [f"{provider}/{model}"]}

    _save(data)
    print(f"Active model set to: {provider}/{model}  (all tiers)")


# ---------------------------------------------------------------------------
# Subcommand: add
# ---------------------------------------------------------------------------


def _cmd_add(name: str, base_url: str, model_name: str | None, api_key_env: str | None) -> None:
    """Add a custom OpenAI-compatible endpoint."""
    data = _load()
    providers = data.setdefault("providers", {})

    if name in providers:
        print(f"Error: provider '{name}' already exists.")
        print(f"  Remove first: prometheus model remove {name}")
        sys.exit(1)

    # Resolve API key env var name
    env_var = api_key_env or _resolve_env_name(name)

    # Determine the actual model ID to use
    model_id = model_name or "default"

    # Build the provider entry
    providers[name] = {
        "base_url": base_url.rstrip("/"),
        "protocol": "openai",
        "api_keys": [{"env": env_var}],
        "models": {
            model_id: {
                "tier": "hard",
                "max_tokens": 65536,
            },
        },
    }

    _save(data)
    print(f"Added provider: {name}")
    print(f"  base_url: {base_url}")
    print(
        f"  api_key:  {env_var}"  # codeql[py/clear-text-logging-sensitive-data] : suppressed via the security dashboard triage
    )  # codeql[py/clear-text-logging-sensitive-data] : env_var is the env-var name (e.g. OPENAI_API_KEY), not the key value
    print(f"  model:    {model_id}")
    print()
    print(
        f"Set API key in ~/.prometheus/.env:  {env_var}=your-key-here"  # codeql[py/clear-text-logging-sensitive-data] : suppressed via the security dashboard triage
    )  # codeql[py/clear-text-logging-sensitive-data] : env_var is the env-var name, not the key value
    print(f"Then activate: prometheus model set {name}/{model_id}")


# ---------------------------------------------------------------------------
# Subcommand: remove
# ---------------------------------------------------------------------------


def _cmd_remove(name: str) -> None:
    """Remove a provider and all its references from routing."""
    data = _load()
    providers = data.get("providers", {})

    if name not in providers:
        print(f"Error: provider '{name}' not found.")
        print(f"  List available: prometheus model list")
        sys.exit(1)

    # Remove from providers
    del providers[name]

    # Remove from routing
    routing = data.get("routing", {})
    for tier_name in list(routing.keys()):
        tier_data = routing.get(tier_name)
        if isinstance(tier_data, dict):
            models_list = tier_data.get("models", [])
            models_list[:] = [
                m for m in models_list if not (isinstance(m, str) and m.startswith(f"{name}/"))
            ]
        elif isinstance(tier_data, list):
            tier_data[:] = [
                m for m in tier_data if not (isinstance(m, str) and m.startswith(f"{name}/"))
            ]

    # Remove empty routing entries
    for tier_name in list(routing.keys()):
        tier_data = routing.get(tier_name)
        models_list = (
            tier_data if isinstance(tier_data, list) else (tier_data or {}).get("models", [])
        )
        if not models_list:
            del routing[tier_name]

    _save(data)
    print(f"Removed provider: {name}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_model_cli(args: list[str]) -> None:
    """Dispatch 'prometheus model <subcommand> ...'."""
    if not args or args[0] in ("-h", "--help", "help"):
        doc = __doc__ or ""
        print(doc.strip() if doc else "")
        return

    cmd = args[0]
    cmd_args = args[1:]

    if cmd == "list":
        _cmd_list()

    elif cmd == "set":
        if not cmd_args:
            print("Usage: prometheus model set <provider/model>")
            print(
                "  Example: prometheus model set openrouter/nvidia/nemotron-3-ultra-550b-a55b:free"
            )
            sys.exit(1)
        _cmd_set(cmd_args[0])

    elif cmd == "add":
        if len(cmd_args) < 2:
            print(
                "Usage: prometheus model add <name> <base_url> [--model MODEL] [--api-key-env VAR]"
            )
            print(
                "  Example: prometheus model add my-local http://localhost:11434/v1 --model llama3"
            )
            sys.exit(1)
        name = cmd_args[0]
        base_url = cmd_args[1]
        model_name = None
        api_key_env = None
        extra = cmd_args[2:]
        for i, a in enumerate(extra):
            if a == "--model" and i + 1 < len(extra):
                model_name = extra[i + 1]
            elif a == "--api-key-env" and i + 1 < len(extra):
                api_key_env = extra[i + 1]
        _cmd_add(name, base_url, model_name, api_key_env)

    elif cmd == "remove":
        if not cmd_args:
            print("Usage: prometheus model remove <name>")
            print("  Example: prometheus model remove my-local")
            sys.exit(1)
        _cmd_remove(cmd_args[0])

    else:
        print(f"Unknown subcommand: {cmd}")
        print(f"  Available: list, set, add, remove")
        sys.exit(1)
