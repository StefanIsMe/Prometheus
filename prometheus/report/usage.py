"""SDK-native LLM usage aggregation for scan reports."""

from __future__ import annotations

import logging
from typing import Any

from agents.usage import Usage, deserialize_usage, serialize_usage


logger = logging.getLogger(__name__)


# Well-known LiteLLM provider prefixes (subset of litellm.provider_list).
# When a model string uses a prefix NOT in this set, it is almost always a
# custom OpenAI-compatible proxy (e.g. TokenRouter, Hermes proxy, internal
# gateway). LiteLLM's completion_cost raises BadRequestError on unknown
# prefixes, which floods the scan log with one traceback per LLM call.
# Skipping the lookup for unknown prefixes keeps the log clean and cost
# tracking honest (we genuinely don't know the per-token price for a
# private proxy without explicit pricing data).
_LITELLM_KNOWN_PROVIDER_PREFIXES: frozenset[str] = frozenset(
    {
        # OpenAI family
        "openai",
        "azure",
        "azure_ai",
        "azure_ad",
        # Anthropic
        "anthropic",
        # Google
        "gemini",
        "vertex_ai-language-models",
        "vertex_ai-anthropic_models",
        "palm",
        # AWS
        "bedrock",
        "sagemaker",
        # Other major providers with native LiteLLM pricing
        "cohere",
        "mistral",
        "replicate",
        "huggingface",
        "together_ai",
        "fireworks_ai",
        "anyscale",
        "openrouter",
        "ai21",
        "groq",
        "deepseek",
        "perplexity",
        "xai",
        "voyage",
        "nlp_cloud",
        "deepinfra",
        "octoai",
        # litellm_proxy etc. — explicitly routable prefixes
        "litellm",
        "litellm_proxy",
        "any-llm",
    }
)


class LLMUsageLedger:
    """Aggregate SDK ``Usage`` objects and attach best-effort cost estimates."""

    def __init__(self) -> None:
        self._total_usage = Usage()
        self._agent_usage: dict[str, Usage] = {}
        self._agent_metadata: dict[str, dict[str, str]] = {}
        self._total_cost = 0.0
        self._agent_cost: dict[str, float] = {}

    def record(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
    ) -> bool:
        if usage is None or not _usage_has_activity(usage):
            return False

        normalized_agent_id = str(agent_id or "unknown")
        estimated_cost = _estimate_litellm_cost(usage, model)

        self._total_usage.add(usage)
        self._agent_usage.setdefault(normalized_agent_id, Usage()).add(usage)

        metadata = self._agent_metadata.setdefault(normalized_agent_id, {})
        if agent_name:
            metadata["agent_name"] = agent_name
        if model:
            metadata["model"] = model

        if estimated_cost is not None:
            self._total_cost += estimated_cost
            self._agent_cost[normalized_agent_id] = (
                self._agent_cost.get(normalized_agent_id, 0.0) + estimated_cost
            )

        return True

    def to_record(self) -> dict[str, Any]:
        record = serialize_usage(self._total_usage)
        record["cost"] = _round_cost(self._total_cost)
        record["cost_source"] = "litellm_estimate"
        record["agents"] = []

        for agent_id in sorted(self._agent_usage):
            usage = self._agent_usage[agent_id]
            metadata = self._agent_metadata.get(agent_id, {})
            agent_record = serialize_usage(usage)
            agent_record.update(
                {
                    "agent_id": agent_id,
                    "agent_name": metadata.get("agent_name") or agent_id,
                    "model": metadata.get("model"),
                    "cost": _round_cost(self._agent_cost.get(agent_id, 0.0)),
                    "cost_source": "litellm_estimate",
                }
            )
            record["agents"].append(agent_record)

        return record

    def hydrate(self, raw_usage: Any) -> None:
        self._total_usage = Usage()
        self._agent_usage.clear()
        self._agent_metadata.clear()
        self._total_cost = 0.0
        self._agent_cost.clear()

        if not isinstance(raw_usage, dict):
            return

        try:
            self._total_usage = deserialize_usage(raw_usage)
        except Exception:
            logger.exception("Failed to hydrate aggregate llm_usage from run.json")
            self._total_usage = Usage()

        self._total_cost = _float_or_zero(raw_usage.get("cost"))
        agents = raw_usage.get("agents") or []
        if not isinstance(agents, list):
            return

        for raw_agent in agents:
            if not isinstance(raw_agent, dict):
                continue
            agent_id = str(raw_agent.get("agent_id") or "").strip()
            if not agent_id:
                continue
            try:
                self._agent_usage[agent_id] = deserialize_usage(raw_agent)
            except Exception:
                logger.exception("Failed to hydrate llm_usage for agent %s", agent_id)
                self._agent_usage[agent_id] = Usage()

            metadata: dict[str, str] = {}
            agent_name = raw_agent.get("agent_name")
            model = raw_agent.get("model")
            if isinstance(agent_name, str) and agent_name:
                metadata["agent_name"] = agent_name
            if isinstance(model, str) and model:
                metadata["model"] = model
            self._agent_metadata[agent_id] = metadata
            self._agent_cost[agent_id] = _float_or_zero(raw_agent.get("cost"))


def _usage_has_activity(usage: Usage) -> bool:
    return bool(
        usage.requests
        or usage.input_tokens
        or usage.output_tokens
        or usage.total_tokens
        or usage.request_usage_entries
    )


def _estimate_litellm_cost(usage: Usage, model: str | None) -> float | None:
    litellm_model = _litellm_model_name(model)
    if not litellm_model:
        return None
    # Short-circuit custom OpenAI-compatible proxies — at this point
    # the model string has been normalized and the provider prefix
    # added back from the local config.  LiteLLM's completion_cost
    # raises BadRequestError on unknown prefixes (TokenRouter,
    # internal gateways, etc.) and the only outcome is noise — we
    # have no pricing data for a private proxy.
    if _is_custom_proxy_model(litellm_model):
        return None

    entries = list(usage.request_usage_entries)
    if not entries:
        return _estimate_litellm_entry_cost(usage, litellm_model)

    total = 0.0
    estimated_any = False
    for entry in entries:
        cost = _estimate_litellm_entry_cost(entry, litellm_model)
        if cost is None:
            continue
        total += cost
        estimated_any = True

    return total if estimated_any else None


def _estimate_litellm_entry_cost(entry: Any, model: str) -> float | None:
    prompt_tokens = _int_or_zero(getattr(entry, "input_tokens", 0))
    completion_tokens = _int_or_zero(getattr(entry, "output_tokens", 0))
    total_tokens = _int_or_zero(getattr(entry, "total_tokens", 0))
    if total_tokens <= 0:
        total_tokens = prompt_tokens + completion_tokens
    if total_tokens <= 0:
        return None

    usage_payload: dict[str, Any] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }
    prompt_details = _details_to_dict(getattr(entry, "input_tokens_details", None))
    completion_details = _details_to_dict(getattr(entry, "output_tokens_details", None))
    if prompt_details:
        usage_payload["prompt_tokens_details"] = prompt_details
    if completion_details:
        usage_payload["completion_tokens_details"] = completion_details

    # DeepSeek v4 direct pricing (LiteLLM doesn't have these yet as of 2026-06).
    # Pricing per 1M tokens. Source: https://api-docs.deepseek.com/quick_start/pricing
    # deepseek-v4-flash: cache-hit $0.0028, cache-miss $0.14, output $0.28
    # deepseek-v4-pro:   cache-hit $0.003625, cache-miss $0.435, output $0.87
    model_lower = model.lower()
    if "deepseek-v4" in model_lower or "deepseek-v4" in model_lower:
        if "v4-pro" in model_lower:
            cache_hit_price = 0.003625 / 1_000_000
            cache_miss_price = 0.435 / 1_000_000
            output_price = 0.87 / 1_000_000
        elif "v4-flash" in model_lower:
            cache_hit_price = 0.0028 / 1_000_000
            cache_miss_price = 0.14 / 1_000_000
            output_price = 0.28 / 1_000_000
        else:
            cache_hit_price = 0.003625 / 1_000_000  # default to pro pricing
            cache_miss_price = 0.435 / 1_000_000
            output_price = 0.87 / 1_000_000

        cached = _int_or_zero(prompt_details.get("cached_tokens", 0))
        uncached = prompt_tokens - cached
        cost = (
            cached * cache_hit_price
            + uncached * cache_miss_price
            + completion_tokens * output_price
        )
        return max(cost, 0.0)

    try:
        from litellm import completion_cost

        cost = completion_cost(
            completion_response={
                "model": model.split("/", 1)[-1],
                "usage": usage_payload,
            },
            model=model,
        )
    except Exception as exc:  # noqa: BLE001 - LiteLLM raises plain Exception for unknown model prices.
        # Use compact one-line log: the full traceback is unhelpful when
        # the only useful info is "this model is not priced by litellm".
        # Use logger.debug with exc_info only if the exception is novel.
        msg = str(exc).splitlines()[0][:200] if str(exc) else "unknown"
        logger.debug("LiteLLM cost estimate unavailable for model %s (%s)", model, msg)
        return None

    return cost if isinstance(cost, int | float) and cost >= 0 else None


def _litellm_model_name(model: str | None) -> str | None:
    if not model:
        return None
    normalized = model.strip()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if normalized.startswith(prefix):
            normalized = normalized.removeprefix(prefix)
            break
    # Auto-prefix known providers when model lacks provider/ prefix.
    # LiteLLM's completion_cost requires provider/model format.
    if "/" not in normalized:
        try:
            from prometheus.config.llm_config import get_config

            config = get_config()
            for provider_name, provider in config.providers.items():
                if normalized in provider.models:
                    normalized = f"{provider_name}/{normalized}"
                    break
        except Exception:
            logger.debug(
                "provider lookup failed for %r, returning normalized as-is",
                normalized,
                exc_info=True,
            )
    return normalized or None


def _is_custom_proxy_model(model: str | None) -> bool:
    """Return True when ``model`` uses a provider prefix that LiteLLM does
    not recognise. Custom OpenAI-compatible proxies (TokenRouter, internal
    gateways, Hermes-routed vendors) fall into this category and must skip
    the LiteLLM cost-lookup path entirely — otherwise litellm.completion_cost
    raises BadRequestError on every LLM call.
    """
    if not model:
        return False
    normalized = model.strip()
    if "/" not in normalized:
        # No prefix — LiteLLM will pick a default provider; let it try.
        return False
    prefix = normalized.split("/", 1)[0].lower()
    if prefix in _LITELLM_KNOWN_PROVIDER_PREFIXES:
        return False
    return True


def _details_to_dict(details: Any) -> dict[str, Any]:
    if details is None:
        return {}
    if isinstance(details, list):
        for item in details:
            result = _details_to_dict(item)
            if result:
                return result
        return {}
    if hasattr(details, "model_dump"):
        return _details_to_dict(details.model_dump())
    if not isinstance(details, dict):
        return {}
    return {str(k): v for k, v in details.items() if v is not None}


def _int_or_zero(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _float_or_zero(value: Any) -> float:
    try:
        result = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return result if result >= 0 else 0.0


def _round_cost(cost: float) -> float:
    return round(max(0.0, cost), 10)
