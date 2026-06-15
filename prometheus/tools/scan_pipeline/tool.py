"""
``run_scan_pipeline`` — Deterministic scan pipeline tool.

Runs recon → fingerprint → vulnerability scan in ONE tool call,
eliminating 5-10 LLM decision turns that would otherwise be needed
for individual tool orchestration. Zero LLM cost beyond this one call.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

logger = logging.getLogger(__name__)

PIPELINE_SCRIPT = "/scripts/scan-pipeline.sh"


@function_tool(timeout=600, strict_mode=False)
async def run_scan_pipeline(
    ctx: RunContextWrapper[Any],
    target_url: str,
    deep: bool = False,
) -> str:
    """Run the deterministic recon+fingerprint+scan pipeline against a target.

    This single tool call replaces 5-10 individual LLM-driven tool calls:
    httpx -tech-detect → whatweb → nmap → naabu → dirsearch → ffuf →
    nuclei → wafw00f → (optional: sqlmap).

    Use this FIRST for every target before doing any manual testing.
    The pipeline outputs structured JSON with technologies, open ports,
    nuclei findings, and WAF detection — all the data you need to plan
    the next steps without burning LLM tokens on mechanical recon tasks.

    Args:
        target_url: The target URL (e.g., https://example.com)
        deep: If True, also runs sqlmap basic check (slower). Default: False.

    Returns:
        JSON summary with per-phase results: technologies detected,
        open ports, directory enumeration results, nuclei findings,
        and WAF detection.
    """
    import asyncio
    import os

    tor_proxy_set = "PROMETHEUS_TOR_PROXY" in os.environ
    allow_direct = os.environ.get("PROMETHEUS_ALLOW_DIRECT", "false").lower() == "true"
    tor_flag = "--tor" if tor_proxy_set else ""
    allow_direct_flag = "--allow-direct" if allow_direct else ""
    deep_flag = "--deep" if deep else ""

    cmd = f"bash {PIPELINE_SCRIPT} {target_url} /workspace/pipeline-output {tor_flag} {allow_direct_flag} {deep_flag}"

    # Execute in sandbox via exec_command — don't actually run here
    # This function returns the command for the agent to execute
    return json.dumps(
        {
            "command": cmd,
            "script": PIPELINE_SCRIPT,
            "tor": bool(tor_flag),
            "allow_direct": bool(allow_direct_flag),
            "deep": deep,
            "instruction": (
                f"Run this command: {cmd}\n"
                f"This will execute the full recon→fingerprint→scan pipeline "
                f"in one shot. Results go to /workspace/pipeline-output/pipeline-summary.json. "
                f"Read that file with cat or Python to get the structured results."
            ),
        },
        indent=2,
    )
