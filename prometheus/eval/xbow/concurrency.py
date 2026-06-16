"""Bounded async gather.

Tiny helper so the runner can fan out up to ``--concurrency N``
challenges in parallel without each one blocking the others. We
wrap each coroutine in an :class:`asyncio.Semaphore` and then hand
the wrapped coroutines to :func:`asyncio.gather`. Failures on one
coroutine resolve to ``None`` in the result list (gather's default
``return_exceptions=False`` would cancel siblings, which is the
wrong behavior for an eval harness — a single broken container
shouldn't kill the other four).
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Iterable, TypeVar

T = TypeVar("T")


async def bounded_gather(
    coros: Iterable[Awaitable[T]],
    n: int,
) -> list[Any]:
    """Run the coroutines with at most ``n`` in flight at once.

    Each coroutine's return value is collected. Exceptions from any
    single coroutine are caught and returned as the string repr of
    the exception in its slot, so one failure doesn't cancel the
    others and the runner can still write a row for every
    challenge.
    """
    if n < 1:
        n = 1
    sem = asyncio.Semaphore(n)

    async def _wrap(c: Awaitable[T]) -> Any:
        async with sem:
            try:
                return await c
            except Exception as exc:  # noqa: BLE001 - eval harness
                return exc

    return await asyncio.gather(*(_wrap(c) for c in coros))


__all__ = ["bounded_gather"]
