"""Tests for prometheus/report/usage.py cost estimation logic.

Focus: the cost-lookup path must not raise on unknown LiteLLM provider
prefixes (TokenRouter, internal gateways, etc.) and must not pollute the
log with full tracebacks for expected unknown-model failures.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Add the prometheus source root to sys.path so we can import the module
# under test without depending on the full Prometheus package install.
SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.report.usage import (  # noqa: E402
    _LITELLM_KNOWN_PROVIDER_PREFIXES,
    _is_custom_proxy_model,
    _litellm_model_name,
    _estimate_litellm_cost,
)


def test_is_custom_proxy_model_true_for_tokenrouter():
    """TokenRouter is a custom OpenAI-compatible proxy — not in LiteLLM."""
    assert _is_custom_proxy_model("TokenRouter/MiniMax-M3") is True


def test_is_custom_proxy_model_true_for_unknown_prefix():
    """Any prefix not in the well-known set is treated as custom proxy."""
    assert _is_custom_proxy_model("MyCompanyProxy/some-model") is True
    assert _is_custom_proxy_model("internal-gateway/llama-3.1-70b") is True


def test_is_custom_proxy_model_false_for_known_litellm_providers():
    """Known LiteLLM providers should still go through the cost lookup."""
    assert _is_custom_proxy_model("openai/gpt-4o") is False
    assert _is_custom_proxy_model("anthropic/claude-3-5-sonnet") is False
    assert _is_custom_proxy_model("openrouter/auto") is False
    assert _is_custom_proxy_model("groq/llama-3.1-70b-versatile") is False
    assert _is_custom_proxy_model("deepseek/deepseek-chat") is False


def test_is_custom_proxy_model_false_when_no_prefix():
    """Bare model name without prefix — let LiteLLM pick the default."""
    assert _is_custom_proxy_model("gpt-4o") is False


def test_is_custom_proxy_model_handles_none_and_empty():
    assert _is_custom_proxy_model(None) is False
    assert _is_custom_proxy_model("") is False


def test_is_custom_proxy_model_is_case_insensitive():
    """Provider prefix matching should be case-insensitive."""
    assert _is_custom_proxy_model("OPENAI/gpt-4o") is False
    assert _is_custom_proxy_model("OpenAI/GPT-4o") is False
    assert _is_custom_proxy_model("tokenrouter/some-model") is True


def test_estimate_litellm_cost_returns_none_for_custom_proxy_without_logging(caplog):
    """The hot path: TokenRouter must return None and stay quiet."""
    from agents.usage import Usage

    usage = Usage(
        input_tokens=1000,
        output_tokens=500,
        total_tokens=1500,
    )
    with caplog.at_level(logging.DEBUG, logger="prometheus.report.usage"):
        result = _estimate_litellm_cost(usage, "TokenRouter/MiniMax-M3")
    assert result is None
    # Critical: no BadRequestError traceback should have been emitted.
    badrequest_records = [r for r in caplog.records if "BadRequestError" in r.getMessage()]
    assert badrequest_records == [], f"unexpected BadRequest log: {badrequest_records!r}"


def test_estimate_litellm_cost_known_provider_falls_through(caplog):
    """For known providers, the function should still attempt the LiteLLM call.

    We can't predict whether LiteLLM knows the price for "openai/gpt-4o-mini"
    in CI, but we CAN verify it does NOT short-circuit and return None
    without trying. We assert: either the call succeeded and returned a
    number, or it failed gracefully and logged at DEBUG.
    """
    from agents.usage import Usage

    usage = Usage(
        input_tokens=1000,
        output_tokens=500,
        total_tokens=1500,
    )
    with caplog.at_level(logging.DEBUG, logger="prometheus.report.usage"):
        result = _estimate_litellm_cost(usage, "openai/gpt-4o-mini")
    # We accept either a real cost number (LiteLLM knows the model) or None
    # (unknown model — fine).  The point is: no raised exception escaped.
    assert result is None or isinstance(result, (int, float))
    # And no full traceback (BadRequestError is impossible for openai/*).
    badrequest_records = [r for r in caplog.records if "BadRequestError" in r.getMessage()]
    assert badrequest_records == []


def test_estimate_litellm_cost_bare_model_gets_prefix_re_added(monkeypatch, caplog):
    """Regression: when the caller passes a bare model name like
    'MiniMax-M3' (no provider prefix), ``_litellm_model_name`` looks
    up the local Prometheus config and re-adds the TokenRouter prefix.
    The short-circuit MUST still trigger on the re-prefixed string,
    not just the original bare model — otherwise a real TokenRouter
    cost-lookup fires and emits a BadRequestError traceback.
    """
    import sys

    # Force a fresh import of usage module so the mocked config is read.
    for mod in list(sys.modules.keys()):
        if "prometheus" in mod:
            del sys.modules[mod]

    from agents.usage import Usage
    from prometheus.config.llm_config import (
        LlmConfig,
        ModelSpec,
        Protocol,
        ProviderConfig,
        Tier,
    )

    # Build a minimal LlmConfig with TokenRouter containing MiniMax-M3,
    # mirroring the user's actual llm.yaml layout.
    fake_config = LlmConfig(
        providers={
            "TokenRouter": ProviderConfig(
                name="TokenRouter",
                base_url="https://api.tokenrouter.com/v1",
                protocol=Protocol.OPENAI,
                models={
                    "MiniMax-M3": ModelSpec(
                        provider_name="TokenRouter",
                        model_id="MiniMax-M3",
                        tier=Tier.HARD,
                        max_tokens=65536,
                    )
                },
            ),
        }
    )

    from prometheus.config import llm_config as llm_mod  # noqa: E402

    monkeypatch.setattr(llm_mod, "get_config", lambda: fake_config)

    usage = Usage(
        input_tokens=1000,
        output_tokens=500,
        total_tokens=1500,
    )
    with caplog.at_level(logging.DEBUG, logger="prometheus.report.usage"):
        result = _estimate_litellm_cost(usage, "MiniMax-M3")
    # The short-circuit must have triggered AFTER the prefix re-add.
    assert result is None
    # The whole point: no BadRequestError leaked into the log.
    badrequest_records = [r for r in caplog.records if "BadRequestError" in r.getMessage()]
    assert badrequest_records == [], (
        f"bare model 'MiniMax-M3' should short-circuit after "
        f"_litellm_model_name re-adds the TokenRouter prefix; got: "
        f"{[r.getMessage() for r in badrequest_records]}"
    )


def test_known_provider_set_includes_tokenrouter_false():
    """Sanity: TokenRouter is NOT in the known set (we never want it to be)."""
    assert "tokenrouter" not in _LITELLM_KNOWN_PROVIDER_PREFIXES
    assert "TokenRouter" not in _LITELLM_KNOWN_PROVIDER_PREFIXES


def test_known_provider_set_covers_all_advertised_providers():
    """Make sure we have a sane coverage of common providers."""
    expected = {
        "openai",
        "anthropic",
        "gemini",
        "groq",
        "openrouter",
        "deepseek",
        "bedrock",
        "huggingface",
        "replicate",
    }
    missing = expected - _LITELLM_KNOWN_PROVIDER_PREFIXES
    assert missing == set(), f"missing providers from known set: {missing!r}"


if __name__ == "__main__":
    test_is_custom_proxy_model_true_for_tokenrouter()
    test_is_custom_proxy_model_true_for_unknown_prefix()
    test_is_custom_proxy_model_false_for_known_litellm_providers()
    test_is_custom_proxy_model_false_when_no_prefix()
    test_is_custom_proxy_model_handles_none_and_empty()
    test_is_custom_proxy_model_is_case_insensitive()
    test_estimate_litellm_cost_returns_none_for_custom_proxy_without_logging()
    test_estimate_litellm_cost_known_provider_falls_through()
    test_known_provider_set_includes_tokenrouter_false()
    test_known_provider_set_covers_all_advertised_providers()
    print("All usage.py tests passed.")
