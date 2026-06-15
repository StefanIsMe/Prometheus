"""``web_search`` — Free web search via DuckDuckGo (ddgs). No API key required."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# Lazy import — ddgs may not be installed in all environments
_ddgs_lock = threading.Lock()
_ddgs = None


def _get_ddgs():
    global _ddgs
    if _ddgs is not None:
        return _ddgs
    with _ddgs_lock:
        if _ddgs is not None:
            return _ddgs
        try:
            from ddgs import DDGS

            _ddgs = DDGS
        except ImportError:
            # Try the older package name
            try:
                from duckduckgo_search import DDGS

                _ddgs = DDGS
            except ImportError:
                raise ImportError("ddgs package not installed. Run: pip install ddgs") from None
    return _ddgs


def _do_search(query: str, max_results: int = 3) -> dict[str, Any]:
    max_results = min(max_results, 3)
    if not query or not query.strip():
        return {"success": False, "error": "Query cannot be empty"}

    logger.info("web_search query (len=%d): %s", len(query), query[:120])

    try:
        DDGS = _get_ddgs()
        results = DDGS().text(query, max_results=max_results)
    except ImportError as exc:
        logger.warning("ddgs not available: %s", exc)
        return {
            "success": False,
            "error": f"Web search unavailable: {exc}",
        }
    except Exception as exc:
        logger.exception("ddgs search failed")
        # Retry once — DuckDuckGo sometimes rate-limits
        try:
            import time

            time.sleep(2)
            DDGS = _get_ddgs()
            results = DDGS().text(query, max_results=max_results)
        except Exception:
            logger.warning("ddgs search retry also failed for query: %s", query[:80], exc_info=True)
            return {
                "success": False,
                "error": f"Web search failed: {exc}",
            }

    if not results:
        return {
            "success": True,
            "query": query,
            "content": "No results found. Try a different or shorter query.",
            "results": [],
        }

    # Format results into a readable block for the agent
    lines = []
    for i, r in enumerate(results, 1):
        title = r.get("title", "No title")
        href = r.get("href", "")
        body = r.get("body", "")
        lines.append(f"{i}. **{title}**\n   URL: {href}\n   {body}\n")

    content = "\n".join(lines)

    return {
        "success": True,
        "query": query,
        "content": content,
        "results": results,
        "result_count": len(results),
    }


@function_tool(timeout=60)
async def web_search(ctx: RunContextWrapper, query: str) -> str:
    """Real-time web search via DuckDuckGo — your primary research tool.

    Free, no API key required. Use it liberally for anything not in
    your training data:

    - Current CVEs, advisories, and 0-days for a specific
      service/version (``OpenSSH 9.6 RCE``, ``Jenkins 2.401.3 auth
      bypass``).
    - Latest WAF / EDR bypass techniques (``Cloudflare WAF SQLi
      bypass 2025``, ``CrowdStrike Falcon evasion``).
    - Tool documentation, flag references, payload galleries.
    - Target reconnaissance / OSINT (company tech stack, leaked
      credentials, exposed assets).
    - Cloud-provider misconfiguration patterns
      (Azure/AWS/GCP-specific attack paths).
    - Bug-bounty writeups and security research papers.
    - Compliance frameworks and CWE/CVSS guidance.
    - Picking the right Python lib / Kali tool for a job (``best 2025
      lib for JWT alg-confusion``).
    - When stuck — looking up the exact error message, ``Access
      denied`` quirks, kernel-specific local-privesc exploits.

    Be specific: include version numbers, error messages, target
    technology, and the exact problem you're stuck on. The more context
    in the query, the more actionable the answer. Vague queries get
    generic answers.

    Returns up to 3 search results with titles, URLs, and snippets.
    This cap is intentional. For exploit research, use at most 3 web
    searches per concrete attack idea, then test the target instead of
    looping on broad searches.

    **Good example queries** (each is a full sentence, names a
    version/product, and asks one concrete thing):

    - ``"OpenSSH 7.4 CVE RCE exploit"``
    - ``"Cloudflare WAF SQLi bypass technique 2025"``
    - ``"Vue.js 3.5 CVE vulnerability security"``
    - ``"Jenkins 2.401.3 authentication bypass exploit"``
    - ``"prototype pollution Node.js gadget chain RCE"``
    - ``"JWT algorithm confusion RS256 HS256 attack"``
    - ``"CORS misconfiguration exploit proof of concept"``
    - ``"WordPress 5.8 WooCommerce 6.1 RCE chain"``

    Args:
        query: The search query — include product name, version, and
            what you're looking for. More specific = better results.
    """
    result = await asyncio.to_thread(_do_search, query)
    return json.dumps(result, ensure_ascii=False, default=str)
