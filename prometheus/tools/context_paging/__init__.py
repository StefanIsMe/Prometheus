"""Phase 4: Tool for retrieving evicted context content.

This tool allows the agent to retrieve full tool outputs that were
truncated during context management. When the agent sees a truncation
message like "[Truncated from 100KB to 50KB. Full output stored with key: abc123]",
it can call this tool with the key to retrieve the full content.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

logger = logging.getLogger(__name__)

# Global overflow store reference (set by the runner)
_overflow_store: Any = None


def set_overflow_store(store: Any) -> None:
    """Set the global overflow store reference."""
    global _overflow_store
    _overflow_store = store


def get_overflow_store() -> Any:
    """Get the global overflow store reference."""
    return _overflow_store


@function_tool(timeout=30)
async def retrieve_evicted_content(
    ctx: RunContextWrapper,
    overflow_key: str,
    max_chars: int = 50000,
) -> str:
    """Retrieve a full tool output that was truncated during context management.

    When you see a message like:
    "[Truncated from 100KB to 50KB. Full output stored with key: abc123]"

    Use this tool with the key to retrieve the full content.

    Args:
        overflow_key: The hash key from the truncation message.
        max_chars: Maximum characters to return (default 50KB). Use a smaller
            value if you only need a specific part of the output.

    Returns:
        The full tool output, or an error message if the key was not found.
    """
    store = get_overflow_store()
    if store is None:
        return json.dumps(
            {
                "success": False,
                "error": "Overflow store not available",
            }
        )

    full_output = store.retrieve(overflow_key)
    if full_output is None:
        return json.dumps(
            {
                "success": False,
                "error": f"Overflow key '{overflow_key}' not found. The content may have been evicted from the overflow store.",
                "stats": store.get_stats(),
            }
        )

    # Truncate if needed
    if len(full_output) > max_chars:
        truncated = full_output[:max_chars]
        # Find a clean break point
        last_newline = truncated.rfind("\n")
        if last_newline > max_chars // 2:
            truncated = truncated[:last_newline]
        return json.dumps(
            {
                "success": True,
                "overflow_key": overflow_key,
                "content": truncated,
                "total_size": len(full_output),
                "returned_size": len(truncated),
                "truncated": True,
                "note": f"Content truncated to {max_chars} chars. Use max_chars parameter to get more.",
            }
        )

    return json.dumps(
        {
            "success": True,
            "overflow_key": overflow_key,
            "content": full_output,
            "total_size": len(full_output),
            "returned_size": len(full_output),
            "truncated": False,
        }
    )


@function_tool(timeout=30)
async def list_evicted_content(
    ctx: RunContextWrapper,
) -> str:
    """List all evicted content keys available for retrieval.

    Use this to see what content has been evicted and can be retrieved
    with the retrieve_evicted_content tool.

    Returns:
        A list of overflow keys with their sizes and storage stats.
    """
    store = get_overflow_store()
    if store is None:
        return json.dumps(
            {
                "success": False,
                "error": "Overflow store not available",
            }
        )

    stats = store.get_stats()

    # Get list of keys from DB if available
    keys = []
    if store._conn:
        try:
            cursor = store._conn.execute(
                "SELECT hash_key, size_bytes, stored_at FROM context_overflow ORDER BY stored_at DESC LIMIT 50"
            )
            for row in cursor.fetchall():
                keys.append(
                    {
                        "key": row[0],
                        "size_bytes": row[1],
                        "stored_at": row[2],
                    }
                )
        except Exception:
            pass

    return json.dumps(
        {
            "success": True,
            "stats": stats,
            "keys": keys,
            "count": len(keys),
        }
    )
