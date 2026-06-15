"""Context management for Prometheus scans.

Implements 5 strategies to control context window bloat:
- Phase 0: Truncate tool outputs at source (terminal 50KB, images stub, curl/HTML 20KB)
- Phase 1: Observation masking (mask tool outputs older than N turns)
- Phase 2: Child agent isolation (structured JSON results only cross boundary)
- Phase 3: System prompt compression (load skills on-demand)
- Phase 4: Demand paging (external store with fault-driven restore)

Based on research:
- "The Complexity Trap" (2508.21433) — observation masking
- "Contextual Memory Virtualisation" (2602.22402) — lossless trimming
- "The Missing Memory Hierarchy" (2603.09023) — demand paging
- "AgentSys" (2602.07398) — hierarchical isolation
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from agents.items import TResponseInputItem

logger = logging.getLogger(__name__)

# === PHASE 0: TRUNCATION LIMITS ===
MAX_TOOL_OUTPUT_BYTES = 50 * 1024  # 50KB per tool output
MAX_IMAGE_OUTPUT_BYTES = 500  # Stub for base64 images
MAX_HTML_OUTPUT_BYTES = 8 * 1024  # 8KB for HTML/curl responses (was 20KB)
MAX_TERMINAL_OUTPUT_BYTES = 15 * 1024  # 15KB for terminal output (was 50KB)

# === PHASE 1: OBSERVATION MASKING ===
MASK_AFTER_TURNS = 2  # Mask tool outputs older than this many turns (was 3)

# === PHASE 4: DEMAND PAGING ===
OVERFLOW_DB_TABLE = "context_overflow"


def _is_base64_image(text: str) -> bool:
    """Check if output contains base64 image data."""
    return "data:image/" in text and "base64," in text


def _is_html_response(text: str) -> bool:
    """Check if output looks like an HTML response."""
    if text.startswith("<!DOCTYPE") or text.startswith("<html"):
        return True
    # Check for large JSON responses (API responses)
    if len(text) > 10000 and (text.startswith("[{") or text.startswith('{"')):
        return True
    return False


def _compute_hash(text: str) -> str:
    """Compute a short hash for overflow storage."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def truncate_tool_output(output: str, tool_name: str = "") -> tuple[str, str | None]:
    """Truncate a tool output to fit within limits.

    Returns (truncated_output, overflow_key).
    If overflow_key is not None, the full output was stored externally.
    """
    if not output or not isinstance(output, str):
        return output, None

    original_size = len(output.encode("utf-8"))

    # Phase 0: Base64 images → stub
    if _is_base64_image(output):
        # Extract approximate size
        size_kb = original_size // 1024
        stub = f"[Screenshot captured — {size_kb}KB base64 image. Use view_screenshot tool to retrieve.]"
        if original_size > MAX_IMAGE_OUTPUT_BYTES:
            overflow_key = _compute_hash(output)
            logger.debug(
                "Truncated base64 image: %dKB → stub (%s)",
                size_kb,
                overflow_key,
            )
            return stub, overflow_key
        return output, None

    # Phase 0: HTML/large responses → truncate
    if _is_html_response(output) and original_size > MAX_HTML_OUTPUT_BYTES:
        truncated = output[:MAX_HTML_OUTPUT_BYTES]
        # Find a clean break point
        last_newline = truncated.rfind("\n")
        if last_newline > MAX_HTML_OUTPUT_BYTES // 2:
            truncated = truncated[:last_newline]
        overflow_key = _compute_hash(output)
        truncated += f"\n\n[Truncated from {original_size // 1024}KB to {len(truncated) // 1024}KB. Full output stored with key: {overflow_key}]"
        logger.debug(
            "Truncated HTML response: %dKB → %dKB (%s)",
            original_size // 1024,
            len(truncated) // 1024,
            overflow_key,
        )
        return truncated, overflow_key

    # Phase 0: Terminal/command output → truncate
    if original_size > MAX_TERMINAL_OUTPUT_BYTES:
        truncated = output[:MAX_TERMINAL_OUTPUT_BYTES]
        # Find a clean break point (prefer line boundary)
        last_newline = truncated.rfind("\n")
        if last_newline > MAX_TERMINAL_OUTPUT_BYTES // 2:
            truncated = truncated[:last_newline]
        overflow_key = _compute_hash(output)
        truncated += f"\n\n[Truncated from {original_size // 1024}KB to {len(truncated) // 1024}KB. Full output stored with key: {overflow_key}]"
        logger.debug(
            "Truncated terminal output: %dKB → %dKB (%s)",
            original_size // 1024,
            len(truncated) // 1024,
            overflow_key,
        )
        return truncated, overflow_key

    return output, None


def mask_old_tool_output(output: str, age_turns: int) -> str:
    """Mask a tool output if it's older than the threshold.

    Returns the original output if recent, or a stub if old.
    """
    if age_turns <= MASK_AFTER_TURNS:
        return output

    if not output or not isinstance(output, str):
        return output

    # Don't mask if it's already a stub
    if output.startswith("[") and ("Truncated" in output or "Screenshot" in output):
        return output

    # Calculate original size for the stub
    size_kb = len(output.encode("utf-8")) // 1024
    return f"[Tool output evicted — {size_kb}KB, {age_turns} turns ago. Re-call tool if needed.]"


def summarize_child_result(output: str, agent_name: str = "") -> str:
    """Extract structured result from child agent output.

    For Phase 2: Only pass structured JSON results to parent,
    not the full conversation history.
    """
    if not output or not isinstance(output, str):
        return output

    # Try to parse as JSON
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            # If it has a success/result structure, keep it
            if "success" in data or "result" in data or "findings" in data:
                return json.dumps(data, indent=2)
            # Otherwise summarize
            keys = list(data.keys())
            return json.dumps(
                {
                    "summary": f"Child agent {agent_name} completed",
                    "keys": keys,
                    "data": data,
                },
                indent=2,
            )
    except (json.JSONDecodeError, TypeError):
        pass

    # For non-JSON output, truncate and summarize
    if len(output) > 2048:
        return (
            f"Child agent {agent_name} output ({len(output) // 1024}KB):\n"
            f"{output[:1024]}\n"
            f"[...truncated...]\n"
            f"{output[-512:]}"
        )

    return output


class ContextOverflowStore:
    """Phase 4: External store for truncated tool outputs.

    Stores full outputs that were truncated, keyed by hash.
    Allows fault-driven paging when the agent needs evicted data.

    Uses SQLite for persistence across sessions.
    """

    def __init__(self, db_path: str | None = None):
        self._memory_store: dict[str, str] = {}  # In-memory cache
        self._db_path = db_path
        self._stats = {
            "stored": 0,
            "retrieved": 0,
            "misses": 0,
        }
        self._conn: Any = None
        if db_path:
            self._init_db(db_path)

    def _init_db(self, db_path: str) -> None:
        """Initialize SQLite storage."""
        import sqlite3

        try:
            self._conn = sqlite3.connect(db_path)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS context_overflow (
                    hash_key TEXT PRIMARY KEY,
                    full_output TEXT NOT NULL,
                    stored_at REAL NOT NULL,
                    size_bytes INTEGER NOT NULL
                )
            """)
            self._conn.commit()
        except Exception:
            logger.debug("Failed to init overflow DB at %s", db_path, exc_info=True)
            self._conn = None

    def store(self, key: str, full_output: str) -> None:
        """Store a full tool output."""
        self._memory_store[key] = full_output
        self._stats["stored"] += 1

        # Persist to SQLite if available
        if self._conn:
            try:
                import time

                self._conn.execute(
                    "INSERT OR REPLACE INTO context_overflow (hash_key, full_output, stored_at, size_bytes) VALUES (?, ?, ?, ?)",
                    (key, full_output, time.time(), len(full_output.encode("utf-8"))),
                )
                self._conn.commit()
            except Exception:
                logger.debug("Failed to persist overflow %s", key, exc_info=True)

        logger.debug("Stored overflow: %s (%d bytes)", key, len(full_output))

    def retrieve(self, key: str) -> str | None:
        """Retrieve a full tool output by key."""
        # Check memory cache first
        result = self._memory_store.get(key)
        if result:
            self._stats["retrieved"] += 1
            return result

        # Check SQLite
        if self._conn:
            try:
                cursor = self._conn.execute(
                    "SELECT full_output FROM context_overflow WHERE hash_key = ?", (key,)
                )
                row = cursor.fetchone()
                if row:
                    self._memory_store[key] = row[0]  # Cache in memory
                    self._stats["retrieved"] += 1
                    return row[0]
            except Exception:
                logger.debug("Failed to retrieve overflow %s from DB", key, exc_info=True)

        self._stats["misses"] += 1
        return None

    def get_stats(self) -> dict[str, int]:
        """Get storage statistics."""
        stats = dict(self._stats)
        # Add DB size if available
        if self._conn:
            try:
                cursor = self._conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM context_overflow"
                )
                row = cursor.fetchone()
                if row:
                    stats["db_entries"] = row[0]
                    stats["db_size_bytes"] = row[1]
            except Exception:
                pass
        return stats

    def clear(self) -> None:
        """Clear all stored outputs."""
        self._memory_store.clear()
        if self._conn:
            try:
                self._conn.execute("DELETE FROM context_overflow")
                self._conn.commit()
            except Exception:
                pass

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


class ContextManagedSession:
    """Wrapper around Session that applies context management.

    Phase 0: Truncates tool outputs at source
    Phase 1: Masks old tool outputs
    Phase 4: Stores overflow for demand paging
    """

    def __init__(
        self,
        inner: Any,  # Session protocol
        overflow_store: ContextOverflowStore | None = None,
        enable_truncation: bool = True,
        enable_masking: bool = True,
        mask_after_turns: int = MASK_AFTER_TURNS,
    ):
        self._inner = inner
        self._overflow = overflow_store or ContextOverflowStore()
        self._enable_truncation = enable_truncation
        self._enable_masking = enable_masking
        self._mask_after_turns = mask_after_turns
        self._turn_counter = 0
        self._item_ages: dict[int, int] = {}  # item_index -> turn when added
        # Protocol attributes (must be plain attrs, not properties)
        self.session_id: str = inner.session_id
        self.session_settings: Any = getattr(inner, "session_settings", None)

    async def get_items(self, limit: int | None = None) -> list[TResponseInputItem]:
        """Retrieve items with Phase 1 masking applied."""
        items = await self._inner.get_items(limit=limit)

        if not self._enable_masking:
            return items

        # Apply observation masking to old tool outputs
        masked_items: list[TResponseInputItem] = []
        total_items = len(items)
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                masked_items.append(item)
                continue

            item_type = item.get("type", "")

            # Calculate age in turns (approximate: items are roughly sequential)
            age_from_end = total_items - i

            # Only mask function_call_output (tool outputs)
            if item_type == "function_call_output" and age_from_end > self._mask_after_turns * 2:
                output = item.get("output", "")
                if isinstance(output, str) and output:
                    masked_output = mask_old_tool_output(output, age_from_end // 2)
                    if masked_output != output:
                        masked_item = dict(item)
                        masked_item["output"] = masked_output
                        masked_items.append(masked_item)  # type: ignore[arg-type]
                        continue

            masked_items.append(item)  # type: ignore[arg-type]

        return masked_items

    async def add_items(self, items: list[TResponseInputItem]) -> None:
        """Add items with Phase 0 truncation applied."""
        if not self._enable_truncation:
            await self._inner.add_items(items)
            return

        processed_items: list[TResponseInputItem] = []
        for item in items:
            if not isinstance(item, dict):
                processed_items.append(item)
                continue

            item_type = item.get("type", "")

            # Phase 0: Truncate function_call_output
            if item_type == "function_call_output":
                output = item.get("output", "")
                if isinstance(output, str) and output:
                    truncated, overflow_key = truncate_tool_output(output)
                    if overflow_key:
                        # Store full output for demand paging
                        self._overflow.store(overflow_key, output)
                        item = dict(item)
                        item["output"] = truncated
                    elif truncated != output:
                        item = dict(item)
                        item["output"] = truncated

            processed_items.append(item)  # type: ignore[arg-type]

        self._turn_counter += 1
        await self._inner.add_items(processed_items)

    async def pop_item(self) -> dict[str, Any] | None:
        """Pop item from inner session."""
        return await self._inner.pop_item()

    async def clear_session(self) -> None:
        """Clear inner session."""
        await self._inner.clear_session()

    def get_overflow_store(self) -> ContextOverflowStore:
        """Get the overflow store for demand paging."""
        return self._overflow

    def get_stats(self) -> dict[str, Any]:
        """Get context management statistics."""
        return {
            "turn_counter": self._turn_counter,
            "truncation_enabled": self._enable_truncation,
            "masking_enabled": self._enable_masking,
            "mask_after_turns": self._mask_after_turns,
            "overflow": self._overflow.get_stats(),
        }


def create_context_managed_session(
    inner: Any,
    enable_truncation: bool = True,
    enable_masking: bool = True,
    mask_after_turns: int = MASK_AFTER_TURNS,
) -> ContextManagedSession:
    """Factory function to create a context-managed session."""
    overflow = ContextOverflowStore()
    return ContextManagedSession(
        inner=inner,
        overflow_store=overflow,
        enable_truncation=enable_truncation,
        enable_masking=enable_masking,
        mask_after_turns=mask_after_turns,
    )
