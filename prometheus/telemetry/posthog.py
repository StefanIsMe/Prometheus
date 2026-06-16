"""Local-only build: external telemetry is disabled.

These stubs preserve the public API (start, finding, end, error) so callers
in the rest of the codebase keep working, but every function is a no-op.
No network traffic leaves the host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    pass  # codeql[py/unsafe-cyclic-import] : stub module — TYPE_CHECKING block is empty, no cycle


def start(*_args: Any, **_kwargs: Any) -> None:  # noqa: D401
    """No-op: external telemetry disabled."""


def finding(*_args: Any, **_kwargs: Any) -> None:
    """No-op: external telemetry disabled."""


def end(*_args: Any, **_kwargs: Any) -> None:
    """No-op: external telemetry disabled."""


def error(*_args: Any, **_kwargs: Any) -> None:
    """No-op: external telemetry disabled."""
