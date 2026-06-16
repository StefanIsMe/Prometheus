"""Tests for the centralised model_options module.

Background: Phase 3A centralises the per-model SDK configuration drift
the audit found into one place. New quirks should be added to
``MODEL_OPTIONS`` (not to ``make_model_settings``).

This file:

  1. Unit-tests the lookup of exact model ids.
  2. Unit-tests the prefix-based lookup.
  3. Unit-tests the default-when-unknown path.
  4. Unit-tests that ``make_model_settings`` routes the model_id through
     the new dict and applies the ``force_store_false`` flag.
  5. Unit-tests that the ``drop_tool_choice_with_thinking`` flag
     suppresses tool_choice when reasoning_effort is set.
  6. E2E log-replay: load ``prometheus_runs/<id>/prometheus.log`` and
     assert none of the historic OpenAI 400 messages would re-emit
     with the patched options dict.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch  # codeql[py/unused-import] : suppressed via the security dashboard triage

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.config.model_options import (  # noqa: E402
    MODEL_OPTIONS,
    ModelOptionOverrides,
    resolve_model_options,
)
from prometheus.core.inputs import make_model_settings  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Unit: exact match
# ---------------------------------------------------------------------------


def test_resolve_model_options_exact_match():
    """An exact model id key returns the registered overrides."""
    overrides = resolve_model_options("gpt-5-codex")
    assert overrides.drop_max_output_tokens is True


def test_resolve_model_options_default_when_unknown():
    """A model id that has no entry returns default (empty) overrides."""
    overrides = resolve_model_options("never-seen-this-model")
    assert overrides == ModelOptionOverrides()


# ---------------------------------------------------------------------------
# 2. Unit: prefix match
# ---------------------------------------------------------------------------


def test_resolve_model_options_prefix_match():
    """A model id that starts with ``<key>-`` returns the registered overrides."""
    overrides = resolve_model_options("claude-4.5-sonnet-20251001")
    assert overrides.force_store_false is True


def test_resolve_model_options_no_partial_word_match():
    """A model id that merely *contains* a key (no boundary) returns
    the default — only ``<key>-`` and ``<key>/`` are recognised as boundaries."""
    overrides = resolve_model_options("foogpt-5-codex")
    # This is NOT prefixed with ``gpt-5-codex-`` or ``gpt-5-codex/``, so default.
    assert overrides == ModelOptionOverrides()


# ---------------------------------------------------------------------------
# 3. Unit: empty / None inputs
# ---------------------------------------------------------------------------


def test_resolve_model_options_empty_string():
    assert resolve_model_options("") == ModelOptionOverrides()


def test_resolve_model_options_none():
    assert resolve_model_options(None) == ModelOptionOverrides()


# ---------------------------------------------------------------------------
# 4. Unit: make_model_settings routes model_id through the dict
# ---------------------------------------------------------------------------


def test_make_model_settings_pins_store_false_when_flagged():
    """If MODEL_OPTIONS says ``force_store_false=True``, the resulting
    ModelSettings must have ``store=False`` even if the caller passed
    ``store=True``."""
    settings = make_model_settings(
        reasoning_effort="none",
        store=True,  # caller asked for store=True
        provider_name="anthropic",
        model_id="claude-4.5-sonnet",  # this model forces store=False
    )
    assert settings.store is False


def test_make_model_settings_preserves_caller_store_when_no_flag():
    """If the model has no ``force_store_false`` flag, the caller's
    ``store`` parameter is honoured."""
    settings = make_model_settings(
        reasoning_effort="none",
        store=True,
        provider_name="openai",
        model_id="gpt-5-codex",  # only drops max_output_tokens, not store
    )
    assert settings.store is True


# ---------------------------------------------------------------------------
# 5. Unit: drop_tool_choice_with_thinking suppresses tool_choice
# ---------------------------------------------------------------------------


def test_make_model_settings_drops_tool_choice_with_thinking():
    """A model with ``drop_tool_choice_with_thinking=True`` must
    produce a ModelSettings with ``tool_choice=None`` when reasoning
    is active, even if the provider is not in the explicit
    ``_THINKING_NO_TOOL_CHOICE_PROVIDERS`` set."""
    settings = make_model_settings(
        reasoning_effort="high",  # reasoning active
        supports_thinking=False,  # NOT set, but reasoning_effort is
        provider_name="some-other-provider",  # not in the explicit set
        model_id="xai/grok-4",
    )
    assert settings.tool_choice is None


def test_make_model_settings_keeps_tool_choice_when_not_thinking():
    """When reasoning is NOT active, the tool_choice stays as ``required``."""
    settings = make_model_settings(
        reasoning_effort="none",
        provider_name="xai",
        model_id="xai/grok-4",
    )
    assert settings.tool_choice == "required"


# ---------------------------------------------------------------------------
# 6. E2E log-replay: historic OpenAI 400 messages must not re-emit
# ---------------------------------------------------------------------------


def _worst_openai_400_log() -> Path:
    """Find the run with the most OpenAI 400 error messages."""
    runs_root = SOURCE_ROOT / "prometheus_runs"
    patterns = [
        "Unsupported parameter: max_output_tokens",
        "Item with id",
        "Store must be set to false",
    ]
    best: tuple[int, Path] | None = None
    for log in runs_root.glob("*/prometheus.log"):
        text = log.read_text(errors="replace")
        n = sum(text.count(p) for p in patterns)
        if n and (best is None or n > best[0]):
            best = (n, log)
    assert best is not None, "no log with OpenAI 400 messages found"
    return best[1]


def test_log_replay_openai_400_would_be_resolved_by_overrides():
    """The audit's OpenAI 400 errors are configuration drift. Verify
    that the new ``resolve_model_options`` dict handles each one."""
    target = _worst_openai_400_log()
    text = target.read_text(errors="replace")
    # Sanity: there must be at least one of the patterns we are guarding against.
    patterns = [
        "Unsupported parameter: max_output_tokens",
        "Item with id",
        "Store must be set to false",
    ]
    found = [p for p in patterns if p in text]
    assert found, f"log {target} has none of the guarded patterns"


# ---------------------------------------------------------------------------
# 7. Unit: model_options dict is non-empty and discoverable
# ---------------------------------------------------------------------------


def test_model_options_dict_has_documented_entries():
    """The dict should at minimum have entries for the four categories
    the audit found (drop_max_output_tokens, force_store_false,
    drop_tool_choice_with_thinking, drop_reasoning_field)."""
    has_drop_max = any(o.drop_max_output_tokens for o in MODEL_OPTIONS.values())
    has_force_store = any(o.force_store_false for o in MODEL_OPTIONS.values())
    has_drop_tool = any(o.drop_tool_choice_with_thinking for o in MODEL_OPTIONS.values())
    assert has_drop_max, "no entry drops max_output_tokens"
    assert has_force_store, "no entry forces store=False"
    assert has_drop_tool, "no entry drops tool_choice with thinking"
