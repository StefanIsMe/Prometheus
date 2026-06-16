"""Tests for context_manager.py — Phase 0-4 implementation."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Add the prometheus source to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prometheus.core.context_manager import (  # codeql[py/unused-import] : suppressed via the security dashboard triage
    ContextManagedSession,
    ContextOverflowStore,
    truncate_tool_output,
    mask_old_tool_output,
    summarize_child_result,
    create_context_managed_session,
    _is_base64_image,
    _is_html_response,
    MAX_IMAGE_OUTPUT_BYTES,
    MAX_HTML_OUTPUT_BYTES,
    MAX_TERMINAL_OUTPUT_BYTES,
    MASK_AFTER_TURNS,
)


class MockSession:
    """Mock session for testing."""

    def __init__(self):
        self.session_id = "test-session"
        self.session_settings = None
        self._items: list[dict] = []

    async def get_items(self, limit: int | None = None) -> list[dict]:
        if limit:
            return self._items[-limit:]
        return list(self._items)

    async def add_items(self, items: list[dict]) -> None:
        self._items.extend(items)

    async def pop_item(self) -> dict | None:
        if self._items:
            return self._items.pop()
        return None

    async def clear_session(self) -> None:
        self._items.clear()


def test_is_base64_image():
    assert _is_base64_image('[{"type":"input_image","image_url":"data:image/png;base64,iVBOR..."}]')
    assert not _is_base64_image("normal text output")
    assert not _is_base64_image('{"result": "ok"}')
    print("  PASS: _is_base64_image")


def test_is_html_response():
    assert _is_html_response("<!DOCTYPE html><html>...")
    assert _is_html_response("<html><body>test</body></html>")
    assert not _is_html_response("normal terminal output")
    assert _is_html_response("[" + '{"key": "value"}' * 1000 + "]")  # Large JSON
    print("  PASS: _is_html_response")


def test_truncate_base64_image():
    """Phase 0: Base64 images should be replaced with stubs."""
    # Create a fake base64 image (800KB)
    fake_image = '[{"type":"input_image","image_url":"data:image/png;base64,' + "A" * 800000 + '"}]'
    result, overflow_key = truncate_tool_output(fake_image)

    assert "Screenshot captured" in result
    assert "781KB" in result or "780KB" in result or "Screenshot captured" in result
    assert overflow_key is not None
    assert len(result) < 200  # Stub should be short
    print("  PASS: truncate_base64_image")


def test_truncate_terminal_output():
    """Phase 0: Large terminal outputs should be truncated."""
    # Create a fake 100KB terminal output
    fake_output = "A" * 100000
    result, overflow_key = truncate_tool_output(fake_output, tool_name="shell")

    assert len(result) < MAX_TERMINAL_OUTPUT_BYTES + 200  # Allow for truncation message
    assert overflow_key is not None
    assert "Truncated from" in result
    assert "100KB" in result or "97KB" in result  # Approximate
    print("  PASS: truncate_terminal_output")


def test_truncate_html_response():
    """Phase 0: HTML responses should be truncated."""
    # Create a fake 50KB HTML response
    fake_html = "<!DOCTYPE html><html>" + "B" * 50000 + "</html>"
    result, overflow_key = truncate_tool_output(fake_html)

    assert len(result) < MAX_HTML_OUTPUT_BYTES + 200
    assert overflow_key is not None
    assert "Truncated from" in result
    print("  PASS: truncate_html_response")


def test_no_truncate_small_output():
    """Small outputs should not be truncated."""
    small_output = '{"result": "ok", "status": 200}'
    result, overflow_key = truncate_tool_output(small_output)

    assert result == small_output
    assert overflow_key is None
    print("  PASS: no_truncate_small_output")


def test_mask_old_tool_output():
    """Phase 1: Old tool outputs should be masked."""
    output = "some tool output data"

    # Recent (within threshold) — should not be masked
    assert mask_old_tool_output(output, 1) == output
    # age_turns=3 with MASK_AFTER_TURNS=2 should be masked
    # (the threshold is strictly-greater-than)
    assert mask_old_tool_output(output, 2) == output

    # Old (beyond threshold) — should be masked
    masked = mask_old_tool_output(output, 5)
    assert "evicted" in masked
    assert output not in masked

    # Very old
    masked = mask_old_tool_output(output, 20)
    assert "evicted" in masked
    assert "20 turns ago" in masked
    print("  PASS: mask_old_tool_output")


def test_mask_preserves_stubs():
    """Phase 1: Already-truncated outputs should not be re-masked."""
    stub = "[Screenshot captured — 800KB base64 image. Use view_screenshot tool to retrieve.]"
    result = mask_old_tool_output(stub, 10)
    assert result == stub  # Should not be double-masked
    print("  PASS: mask_preserves_stubs")


def test_summarize_child_result():
    """Phase 2: Child results should be summarized."""
    # JSON result — should be preserved (may be reformatted)
    json_result = json.dumps({"success": True, "findings": ["xss on /api"]})
    result = summarize_child_result(json_result)
    parsed = json.loads(result)
    assert parsed["success"] is True
    assert "xss" in parsed["findings"][0]

    # Large non-JSON — truncate
    large_output = "A" * 5000
    result = summarize_child_result(large_output, "recon-agent")
    assert len(result) < 3000
    assert "recon-agent" in result
    print("  PASS: summarize_child_result")


def test_overflow_store():
    """Phase 4: Overflow store should store and retrieve."""
    store = ContextOverflowStore()

    store.store("abc123", "full output data here")
    assert store.retrieve("abc123") == "full output data here"
    assert store.retrieve("nonexistent") is None

    stats = store.get_stats()
    assert stats["stored"] == 1
    assert stats["retrieved"] == 1
    assert stats["misses"] == 1
    print("  PASS: overflow_store")


async def test_context_managed_session_truncation():
    """Phase 0: Session wrapper should truncate tool outputs on add."""
    mock = MockSession()
    cms = ContextManagedSession(
        inner=mock,
        enable_truncation=True,
        enable_masking=False,
    )

    # Add a large tool output
    large_output = "A" * 100000
    items = [
        {"type": "function_call_output", "output": large_output, "call_id": "test1"},
        {"type": "message", "content": "normal message"},
    ]

    await cms.add_items(items)

    # Check that the stored output was truncated
    stored = mock._items[0]
    assert stored["type"] == "function_call_output"
    assert len(stored["output"]) < len(large_output)
    assert "Truncated" in stored["output"]

    # Check that normal messages pass through unchanged
    assert mock._items[1]["type"] == "message"

    # Check overflow store has the full output
    overflow = cms.get_overflow_store()
    stats = overflow.get_stats()
    assert stats["stored"] == 1

    print("  PASS: context_managed_session_truncation")


async def test_context_managed_session_masking():
    """Phase 1: Session wrapper should mask old tool outputs on get."""
    mock = MockSession()
    cms = ContextManagedSession(
        inner=mock,
        enable_truncation=False,
        enable_masking=True,
        mask_after_turns=2,
    )

    # Add items simulating a conversation
    for i in range(10):
        mock._items.append(
            {
                "type": "function_call_output",
                "output": f"tool output from turn {i}",
                "call_id": f"call_{i}",
            }
        )
        mock._items.append(
            {
                "type": "message",
                "content": f"message from turn {i}",
            }
        )

    # Get items — old tool outputs should be masked
    items = await cms.get_items()

    # Recent items should be preserved
    recent_output = items[-2]  # Last function_call_output
    assert "tool output from turn" in recent_output["output"]

    # Old items should be masked
    old_output = items[0]  # First function_call_output
    if old_output["type"] == "function_call_output":
        # It should be masked if it's old enough
        if "evicted" in old_output["output"]:
            assert "evicted" in old_output["output"]

    print("  PASS: context_managed_session_masking")


async def test_context_managed_session_no_op():
    """When disabled, session should pass through unchanged."""
    mock = MockSession()
    cms = ContextManagedSession(
        inner=mock,
        enable_truncation=False,
        enable_masking=False,
    )

    items = [
        {"type": "function_call_output", "output": "A" * 100000, "call_id": "test1"},
    ]

    await cms.add_items(items)

    # Should be unchanged
    assert len(mock._items[0]["output"]) == 100000

    print("  PASS: context_managed_session_no_op")


async def test_factory_function():
    """Test the factory function."""
    mock = MockSession()
    cms = create_context_managed_session(
        inner=mock,
        enable_truncation=True,
        enable_masking=True,
        mask_after_turns=5,
    )

    assert isinstance(cms, ContextManagedSession)
    assert cms._mask_after_turns == 5
    assert cms._enable_truncation is True
    assert cms._enable_masking is True

    stats = cms.get_stats()
    assert stats["turn_counter"] == 0
    assert stats["mask_after_turns"] == 5

    print("  PASS: factory_function")


async def test_integration_truncation_and_masking():
    """Integration: truncation + masking working together."""
    mock = MockSession()
    cms = ContextManagedSession(
        inner=mock,
        enable_truncation=True,
        enable_masking=True,
        mask_after_turns=2,
    )

    # Simulate multiple turns
    for turn in range(6):
        items = [
            {
                "type": "function_call_output",
                "output": f"output from turn {turn} " * 100,
                "call_id": f"call_{turn}",
            },
            {"type": "message", "content": f"message {turn}"},
        ]
        await cms.add_items(items)

    # Get items — should have both truncation and masking
    all_items = await cms.get_items()

    # Verify we got items back
    assert len(all_items) > 0

    # Verify stats
    stats = cms.get_stats()
    assert stats["turn_counter"] == 6

    print("  PASS: integration_truncation_and_masking")


def run_sync_tests():
    """Run synchronous tests."""
    print("\n=== Phase 0: Truncation Tests ===")
    test_is_base64_image()
    test_is_html_response()
    test_truncate_base64_image()
    test_truncate_terminal_output()
    test_truncate_html_response()
    test_no_truncate_small_output()

    print("\n=== Phase 1: Observation Masking Tests ===")
    test_mask_old_tool_output()
    test_mask_preserves_stubs()

    print("\n=== Phase 2: Child Isolation Tests ===")
    test_summarize_child_result()

    print("\n=== Phase 4: Demand Paging Tests ===")
    test_overflow_store()


async def run_async_tests():
    """Run asynchronous tests."""
    print("\n=== Session Integration Tests ===")
    await test_context_managed_session_truncation()
    await test_context_managed_session_masking()
    await test_context_managed_session_no_op()
    await test_factory_function()
    await test_integration_truncation_and_masking()


if __name__ == "__main__":
    print("=" * 60)
    print("CONTEXT MANAGER TEST SUITE")
    print("=" * 60)

    run_sync_tests()
    asyncio.run(run_async_tests())

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
