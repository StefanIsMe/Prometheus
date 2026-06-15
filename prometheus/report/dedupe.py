"""SDK-native vulnerability-report deduplication."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.multi_provider import MultiProvider
from openai.types.responses import ResponseOutputMessage

from prometheus.config import load_settings
from prometheus.config.models import (
    DEFAULT_MODEL_RETRY,
    normalize_model_name,
)
from prometheus.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents.items import ModelResponse


logger = logging.getLogger(__name__)

DEDUPE_SYSTEM_PROMPT = """You are an expert vulnerability report deduplication judge.
Your task is to determine if a candidate vulnerability report describes the SAME vulnerability
as any existing report.

CRITICAL DEDUPLICATION RULES:

1. SAME VULNERABILITY means:
   - Same root cause (e.g., "missing input validation" not just "SQL injection")
   - Same affected component/endpoint/file (exact match or clear overlap)
   - Same exploitation method or attack vector
   - Would be fixed by the same code change/patch

2. NOT DUPLICATES if:
   - Different endpoints even with same vulnerability type (e.g., SQLi in /login vs /search)
   - Different parameters in same endpoint (e.g., XSS in 'name' vs 'comment' field)
   - Different root causes (e.g., stored XSS vs reflected XSS in same field)
   - Different severity levels due to different impact
   - One is authenticated, other is unauthenticated

3. ARE DUPLICATES even if:
   - Titles are worded differently
   - Descriptions have different level of detail
   - PoC uses different payloads but exploits same issue
   - One report is more thorough than another
   - Minor variations in technical analysis

COMPARISON GUIDELINES:
- Focus on the technical root cause, not surface-level similarities
- Same vulnerability type (SQLi, XSS) doesn't mean duplicate - location matters
- Consider the fix: would fixing one also fix the other?
- When uncertain, lean towards NOT duplicate

FIELDS TO ANALYZE:
- title, description: General vulnerability info
- target, endpoint, method: Exact location of vulnerability
- technical_analysis: Root cause details
- poc_description: How it's exploited
- impact: What damage it can cause

Respond with a single JSON object and nothing else:

{
  "is_duplicate": true,
  "duplicate_id": "vuln-0001",
  "confidence": 0.95,
  "reason": "Both reports describe SQL injection in /api/login via the username parameter"
}

Or, if not a duplicate:

{
  "is_duplicate": false,
  "duplicate_id": "",
  "confidence": 0.90,
  "reason": "Different endpoints: candidate is /api/search, existing is /api/login"
}

Rules:
- ``is_duplicate`` is a boolean.
- ``duplicate_id`` is the exact id from existing reports, or "" if not a duplicate.
- ``confidence`` is a number between 0 and 1.
- ``reason`` is a specific explanation mentioning endpoint/parameter/root cause.
- Output ONLY the JSON object — no surrounding prose, no code fences."""


def _prepare_report_for_comparison(report: dict[str, Any]) -> dict[str, Any]:
    relevant_fields = [
        "id",
        "title",
        "description",
        "impact",
        "target",
        "technical_analysis",
        "poc_description",
        "endpoint",
        "method",
    ]

    cleaned = {}
    for field in relevant_fields:
        if report.get(field):
            value = report[field]
            if isinstance(value, str) and len(value) > 8000:
                value = value[:8000] + "...[truncated]"
            cleaned[field] = value

    return cleaned


def _parse_dedupe_response(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in dedupe response: {content[:500]}")
    parsed = json.loads(text[start : end + 1])

    duplicate_id = str(parsed.get("duplicate_id") or "")[:64]
    reason = str(parsed.get("reason") or "")[:500]
    try:
        confidence = float(parsed.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0

    return {
        "is_duplicate": bool(parsed.get("is_duplicate", False)),
        "duplicate_id": duplicate_id,
        "confidence": confidence,
        "reason": reason,
    }


def _extract_text(response: ModelResponse) -> str:
    parts: list[str] = []
    for item in response.output:
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(text)
    return "".join(parts)


async def check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any]:
    if not existing_reports:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 1.0,
            "reason": "No existing reports to compare against",
        }

    try:
        settings = load_settings()
        from prometheus.config.models import configure_sdk_model_defaults

        resolution = configure_sdk_model_defaults(settings)
        model_name = settings.llm.model
        if not model_name:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "No LLM model configured; skipping dedupe check",
            }

        candidate_cleaned = _prepare_report_for_comparison(candidate)
        existing_cleaned = [_prepare_report_for_comparison(r) for r in existing_reports]
        comparison_data = {"candidate": candidate_cleaned, "existing_reports": existing_cleaned}

        user_msg = (
            f"Compare this candidate vulnerability against existing reports:\n\n"
            f"{json.dumps(comparison_data, indent=2)}\n\n"
            f"Respond with ONLY the JSON object described in the system prompt."
        )

        resolved_model = normalize_model_name(model_name)
        # Use unknown_prefix_mode="model_id" so non-SDK prefixed model
        # names pass through verbatim to the resolved gateway.
        model = MultiProvider(unknown_prefix_mode="model_id").get_model(resolved_model)
        response = None
        # Phase 4D: wrap the dedupe model call in a small retry loop for
        # transient connection errors. A representative run died here
        # on an ``openai.APIConnectionError`` mid-iteration; after
        # exhaustion we return a no-op so the report writer does not
        # crash.
        from openai import APIConnectionError

        try:
            import httpx
        except ImportError:  # pragma: no cover
            httpx = None  # type: ignore[assignment]

        async def _stream_once() -> Any:
            async for event in model.stream_response(
                system_instructions=DEDUPE_SYSTEM_PROMPT,
                input=user_msg,
                model_settings=ModelSettings(
                    retry=DEFAULT_MODEL_RETRY,
                    include_usage=True,
                    store=False,
                ),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ):
                yield event

        _RETRYABLE = (APIConnectionError,)
        if httpx is not None:
            _RETRYABLE = _RETRYABLE + (httpx.ConnectError, httpx.ReadError)  # type: ignore[assignment]

        response = None
        last_exc: BaseException | None = None
        for _attempt in range(1, 4):  # 3 attempts
            try:
                async for event in _stream_once():
                    event_response = getattr(event, "response", None)
                    if event_response is not None:
                        response = event_response
                break  # success
            except _RETRYABLE as exc:  # type: ignore[misc]
                last_exc = exc
                logger.warning(
                    "dedupe model call transient connection error (attempt %d/3): %s",
                    _attempt,
                    exc,
                )
                import asyncio as _asyncio

                await _asyncio.sleep(0.5 * (2 ** (_attempt - 1)))
                continue
        if response is None and last_exc is not None:
            logger.warning(
                "dedupe model call failed after retries; returning no-op: %s",
                last_exc,
            )
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": f"dedupe model call failed: {last_exc}",
            }
        if response is None:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty stream response from LLM",
            }
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.record_sdk_usage(
                agent_id="dedupe",
                agent_name="dedupe",
                model=resolved_model,
                usage=response.usage,
            )
        content = _extract_text(response)
        if not content:
            return {
                "is_duplicate": False,
                "duplicate_id": "",
                "confidence": 0.0,
                "reason": "Empty response from LLM",
            }

        result = _parse_dedupe_response(content)

        logger.info(
            "Deduplication check: is_duplicate=%s, confidence=%.2f, reason=%s",
            result["is_duplicate"],
            result["confidence"],
            result["reason"][:100],
        )

    except Exception as e:
        logger.exception("Error during vulnerability deduplication check")
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": 0.0,
            "reason": f"Deduplication check failed: {e}",
            "error": str(e),
        }
    else:
        return result
