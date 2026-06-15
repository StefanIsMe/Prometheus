"""Per-model option overrides for the OpenAI Agents SDK.

Phase 3A of the audit plan: one place to encode the configuration drift
the audit found between the model layer and the harness.

Each entry in :data:`MODEL_OPTIONS` is keyed by an exact model id; the
sub-dict may match by prefix when ``"model_prefix": True`` is set. The
:func:`resolve_model_options` helper looks up the entry that best
matches ``model_id`` and returns a :class:`ModelOptionOverrides` value
object with the fields the harness needs to apply at call time.

New quirks discovered in production should be added here (not in
``make_model_settings``); that keeps the drift visible in one place
and makes the next model's configuration review trivial.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ModelOptionOverrides:
    """All overrides the harness might apply for a given model.

    Defaults are conservative — every flag is "off" so a model we have
    never seen gets the existing behaviour.
    """

    # The SDK uses ``max_output_tokens`` on Chat-Completions and
    # ``max_completion_tokens`` on the Responses API. Some upstreams
    # (and the SDK on older versions) reject ``max_output_tokens``;
    # this flag tells :func:`make_model_settings` to drop the field
    # from the model_settings payload entirely.
    drop_max_output_tokens: bool = False

    # Pin ``store=False`` for ALL multi-turn Responses runs. The audit
    # found two scans where the SDK persisted responses and a later
    # turn failed with "Item with id … not found" because the persisted
    # item was no longer available. Default off so existing tests that
    # pass ``store=True`` are unaffected.
    force_store_false: bool = False

    # Suppress tool_choice when thinking mode is active. The audit
    # found a few providers (besides DeepSeek) that reject tool_choice
    # while reasoning is enabled; the new code path picks them up via
    # this flag in addition to the explicit set in
    # ``_THINKING_NO_TOOL_CHOICE_PROVIDERS``.
    drop_tool_choice_with_thinking: bool = False

    # Some providers choke on the ``reasoning`` field even when the
    # model's reasoning_effort is set. Setting this suppresses it.
    drop_reasoning_field: bool = False

    # Extra kwargs merged into the ModelSettings constructor. Use
    # sparingly — prefer explicit flags above.
    extra_body_passthrough: dict[str, Any] = field(default_factory=dict)


# Phase 3C: the model ids seen in the audit. Keep this list short —
# each entry represents a real production failure, not a hypothetical.
MODEL_OPTIONS: dict[str, ModelOptionOverrides] = {
    # "Unsupported parameter: max_output_tokens" — the SDK was passing
    # max_output_tokens to a model that expects max_completion_tokens.
    # Drop the field so the SDK falls back to its own default.
    "gpt-5-codex": ModelOptionOverrides(drop_max_output_tokens=True),
    "gpt-5.1-codex": ModelOptionOverrides(drop_max_output_tokens=True),
    "gpt-5.1-codex-mini": ModelOptionOverrides(drop_max_output_tokens=True),
    # "Item with id … not found" — multi-turn Responses runs that
    # persisted items but lost them on the next turn. Force store=False.
    "claude-4.5-sonnet": ModelOptionOverrides(force_store_false=True),
    "claude-4.5-opus": ModelOptionOverrides(force_store_false=True),
    # "Thinking mode does not support this tool_choice" — providers
    # in the audit that reject tool_choice while thinking is on.
    "xai/grok-4": ModelOptionOverrides(
        drop_tool_choice_with_thinking=True,
        force_store_false=True,
    ),
    "xai/grok-4-fast": ModelOptionOverrides(
        drop_tool_choice_with_thinking=True,
        force_store_false=True,
    ),
}


def resolve_model_options(
    model_id: str | None,
    *,
    provider_name: str = "",
) -> ModelOptionOverrides:
    """Return the overrides that apply to ``model_id`` (or empty defaults).

    Lookup order:

    1. Exact match on ``model_id`` in :data:`MODEL_OPTIONS`.
    2. Prefix match (``model_id`` starts with the key + ``/``).
    3. Empty :class:`ModelOptionOverrides` so the call-site falls through
       to the existing behaviour.

    ``provider_name`` is currently unused but is part of the signature
    so a future second lookup pass (provider-based quirks) doesn't
    need a refactor at the call site.
    """
    if not model_id:
        return ModelOptionOverrides()
    # Exact match first.
    if model_id in MODEL_OPTIONS:
        return MODEL_OPTIONS[model_id]
    # Prefix match: the key + "/" is a path-prefix boundary.
    for key, overrides in MODEL_OPTIONS.items():
        if model_id.startswith(f"{key}/") or model_id.startswith(f"{key}-"):
            return overrides
    return ModelOptionOverrides()


__all__ = ["MODEL_OPTIONS", "ModelOptionOverrides", "resolve_model_options"]
