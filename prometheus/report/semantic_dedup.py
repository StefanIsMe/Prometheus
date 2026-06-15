"""Semantic dedup — embedding-based near-duplicate detection.

Extends the existing deterministic dedup in
:mod:`prometheus.report.dedupe` with an embedding-similarity pass.
Falls back gracefully when no embedding model is available
(:func:`_get_embedder` returns ``None``).

Two findings are considered duplicates when their cosine similarity
is ``>= threshold`` (default 0.85). The dedup is a *secondary* pass;
the deterministic ``(vuln_type, endpoint, parameter)`` key match
always wins.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

logger = logging.getLogger(__name__)


DEFAULT_THRESHOLD = 0.85


@dataclass
class _CachedEmbeddings:
    text: str
    vec: list[float]


def _stringify(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("title", "vuln_type", "endpoint", "parameter", "description", "impact"):
        v = finding.get(key)
        if isinstance(v, str):
            parts.append(v)
    return " | ".join(parts)


# ----------------------------------------------------------------------
# Embedder resolution
# ----------------------------------------------------------------------
def _get_embedder():
    """Return a callable ``text -> list[float]`` or ``None`` if unavailable.

    Tries the configured Hermes provider first; falls back to a
    deterministic hash-based stub so dedup is always defined.
    """
    try:
        from prometheus.config.hermes_bridge import resolve_active_hermes_model
        from prometheus.config.llm_config import resolve_model, get_config  # type: ignore

        _ = resolve_active_hermes_model()  # warm the bridge
        _ = get_config()
    except Exception:
        pass
    try:
        # When an OpenAI-compatible gateway is configured and exposes
        # ``/v1/embeddings``, use it. Otherwise we use the stub.
        import os
        import httpx

        base = os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_API_BASE") or ""
        key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY") or ""
        if base and key:
            client = httpx.Client(
                base_url=base, timeout=20.0, headers={"Authorization": f"Bearer {key}"}
            )

            def embed(texts: list[str]) -> list[list[float]]:
                r = client.post(
                    "/embeddings", json={"model": "text-embedding-3-small", "input": texts}
                )
                r.raise_for_status()
                return [d["embedding"] for d in r.json()["data"]]

            return embed
    except Exception:
        pass
    return _hash_embedder


def _hash_embedder(texts: list[str]) -> list[list[float]]:
    """Deterministic stub: 64-dim trigram-hash projection.

    Not a real embedding — but stable across runs and good enough to
    flag obvious wording variants while keeping unrelated findings
    apart. Cosine distance is dominated by token overlap, which is
    exactly what we want for a fallback.
    """
    import hashlib

    out: list[list[float]] = []
    for text in texts:
        vec = [0.0] * 64
        norm = (text or "").lower()
        for i in range(len(norm) - 2):
            trigram = norm[i : i + 3]
            h = int(hashlib.md5(trigram.encode("utf-8")).hexdigest()[:8], 16)
            idx = h % 64
            sign = 1.0 if (h & 1) else -1.0
            vec[idx] += sign
        norm_v = math.sqrt(sum(x * x for x in vec)) or 1.0
        out.append([x / norm_v for x in vec])
    return out


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (na * nb)


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def semantic_dedup(
    findings: Iterable[dict[str, Any]],
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deduplicate findings by embedding similarity.

    Returns ``(kept, dropped)``. The first finding in a near-duplicate
    cluster is kept; later ones are dropped. Cluster members are
    attached to the kept finding's ``merged_from`` list.
    """
    items = [f for f in findings if isinstance(f, dict)]
    if not items:
        return [], []

    embedder = _get_embedder()
    try:
        vecs = embedder([_stringify(f) for f in items])
    except Exception as exc:
        logger.warning("embedder failed; skipping semantic dedup: %s", exc)
        return items, []

    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    kept_vecs: list[list[float]] = []
    for f, v in zip(items, vecs):
        merged_into: int | None = None
        for idx, kv in enumerate(kept_vecs):
            sim = _cosine(v, kv)
            if sim >= threshold:
                merged_into = idx
                break
        if merged_into is None:
            f = dict(f)
            f.setdefault("merged_from", [])
            kept.append(f)
            kept_vecs.append(list(v))
        else:
            kept[merged_into].setdefault("merged_from", []).append(
                {"id": f.get("id"), "title": f.get("title"), "endpoint": f.get("endpoint")}
            )
            dropped.append(f)
    logger.info(
        "semantic_dedup: %d in, %d kept, %d dropped (threshold=%.2f)",
        len(items),
        len(kept),
        len(dropped),
        threshold,
    )
    return kept, dropped


__all__ = ["DEFAULT_THRESHOLD", "semantic_dedup"]
