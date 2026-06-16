"""``deep_audit`` — browser-based deep vulnerability testing tool.

Extends live_verification beyond curl GET/HEAD with:
- Browser automation for Cloudflare bypass
- Differential response analysis
- Auth flow tracing
- Rate limit probing
- Automated PoC generation
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.core.deep_audit import (
    DifferentialResult,
    analyze_rate_limit,
    build_auth_flow_trace_script,
    build_deep_audit_plan,
    fingerprint_response,
    generate_bugcrowd_report,
    generate_poc_script,
)

logger = logging.getLogger(__name__)


@function_tool
async def run_differential_analysis(
    ctx: RunContextWrapper[Any],
    endpoint: str,
    test_values_json: str,
    description: str = "",
) -> str:
    """Test an endpoint with multiple inputs and check for differential responses.

    Use this when you suspect an endpoint returns different responses based on
    input (e.g., account enumeration, IDOR). Pass test_values_json as a JSON
    array of test inputs. The caller must have already made the HTTP requests
    and collected responses.

    Args:
        endpoint: The URL that was tested
        test_values_json: JSON array of test input values (e.g., '["test@a.com", "test@b.com"]')
        description: What the test is checking for
    """
    try:
        test_values = json.loads(test_values_json)
    except json.JSONDecodeError:
        return f"ERROR: Invalid JSON in test_values_json: {test_values_json[:200]}"

    return json.dumps(
        {
            "endpoint": endpoint,
            "test_values_count": len(test_values),
            "description": description,
            "instruction": "Call analyze_differential() with the actual response fingerprints after making HTTP requests",
            "next_steps": [
                f"Make HTTP requests to {endpoint} with each test value",
                "Collect status_code, body, headers for each response",
                "Call fingerprint_response() on each",
                "Call analyze_differential() with the fingerprints",
            ],
        },
        indent=2,
    )


@function_tool
async def get_auth_flow_trace_script(
    ctx: RunContextWrapper[Any],
    login_url: str,
    email: str,
) -> str:
    """Get a Python script that traces an auth flow via browser automation.

    The script uses browser-harness to navigate to a login page, submit an
    email, and capture all network requests made during the flow. Execute
    the returned script in the sandbox with browser-harness available.

    Args:
        login_url: The login page URL to test
        email: The email address to submit
    """
    script = build_auth_flow_trace_script(login_url, email)
    return json.dumps(
        {
            "login_url": login_url,
            "email": email,
            "script_length": len(script),
            "instruction": "Execute this script in the sandbox with Chromium CDP running on port 9222",
            "script": script,
        },
        indent=2,
    )


@function_tool
async def get_deep_audit_plan(
    ctx: RunContextWrapper[Any],
    target_url: str,
    finding_hint: str = "",
) -> str:
    """Get a structured audit plan for deep testing a target.

    Returns a phased plan the agent can execute step by step. Each phase
    specifies which tool to use and what steps to perform.

    Args:
        target_url: The target URL to audit
        finding_hint: Optional hint about what vulnerability to look for
    """
    plan = build_deep_audit_plan(target_url, finding_hint)
    return json.dumps(plan, indent=2)


@function_tool
async def generate_verified_poc(
    ctx: RunContextWrapper[Any],
    finding_title: str,
    endpoint: str,
    method: str,
    request_body_template: str,
    test_cases_json: str,
) -> str:
    """Generate an executable PoC script from collected test evidence.

    Args:
        finding_title: Title of the vulnerability
        endpoint: The vulnerable endpoint URL
        method: HTTP method (GET, POST, etc.)
        request_body_template: Request body with {input} placeholder for the test value
        test_cases_json: JSON array of test cases, each with 'value', 'expected_status', 'description'
    """
    try:
        test_cases = json.loads(test_cases_json)
    except json.JSONDecodeError:
        return f"ERROR: Invalid JSON in test_cases_json: {test_cases_json[:200]}"

    poc = generate_poc_script(
        finding_title=finding_title,
        endpoint=endpoint,
        method=method,
        request_body_template=request_body_template,
        test_cases=test_cases,
    )

    return json.dumps(
        {
            "finding_title": finding_title,
            "endpoint": endpoint,
            "poc_script": poc,
            "poc_length": len(poc),
            "instruction": "Save this script and execute it to verify the vulnerability",
        },
        indent=2,
    )


@function_tool
async def build_bugcrowd_submission(
    ctx: RunContextWrapper[Any],
    title: str,
    target: str,
    endpoint: str,
    description: str,
    poc_steps_json: str,
    distinct_responses: int,
    response_classes_json: str,
    remediation_json: str,
    cwe: str = "CWE-203",
    cvss_score: float = 5.3,
) -> str:
    """Generate a complete Bugcrowd submission from audit results.

    Args:
        title: Vulnerability title
        target: Target domain (e.g., 'openai.com')
        endpoint: The vulnerable endpoint URL
        description: Vulnerability description
        poc_steps_json: JSON array of PoC step descriptions
        distinct_responses: Number of distinct response types observed
        response_classes_json: JSON dict mapping response class -> test values
        remediation_json: JSON array of remediation steps
        cwe: CWE identifier
        cvss_score: CVSS score
    """
    try:
        poc_steps = json.loads(poc_steps_json)
        remediation = json.loads(remediation_json)
        response_classes = json.loads(response_classes_json)
    except json.JSONDecodeError as e:
        return f"ERROR: Invalid JSON: {e}"

    # Build a mock DifferentialResult for the report generator
    # In practice, the agent would pass the real result
    diff_result = DifferentialResult(
        endpoint=endpoint,
        test_values=[],
        fingerprints=[],
        distinct_responses=distinct_responses,
        is_differential=distinct_responses > 1,
        response_classes=response_classes,
        verdict="account_enumeration" if distinct_responses > 1 else "uniform",
        confidence=0.85,
        evidence=f"Distinct responses: {distinct_responses}",
    )

    report = generate_bugcrowd_report(
        title=title,
        target=target,
        endpoint=endpoint,
        description=description,
        poc_steps=poc_steps,
        differential_result=diff_result,
        remediation=remediation,
        cwe=cwe,
        cvss_score=cvss_score,
    )

    return json.dumps(report, indent=2)


@function_tool
async def lookup_bugcrowd_vrt(
    ctx: RunContextWrapper[Any],
    query: str,
    cwe: str = "",
    title: str = "",
    description: str = "",
) -> str:
    """Look up the Bugcrowd Vulnerability Rating Taxonomy (VRT) to classify a finding.

    Use this BEFORE calling create_vulnerability_report or build_bugcrowd_submission
    when scanning Bugcrowd targets. The VRT maps vulnerability types to priority levels
    (P1=Critical through P5=Informational).

    Args:
        query: Search query (e.g. "xss", "sql injection", "ssrf", "idor").
               Or pass cwe/title/description for automatic classification.
        cwe: CWE identifier (e.g. "CWE-79") for precise matching.
        title: Finding title for keyword-based classification.
        description: Finding description for fuzzy matching.
    """
    from prometheus.core.vrt_classifier import get_vrt_classifier

    vrt = get_vrt_classifier()

    # If cwe/title/description provided, do automatic classification
    if cwe or title:
        result = vrt.classify(
            title=title,
            description=description,
            cwe=cwe,
        )
        return json.dumps(
            {
                "classification": result,
                "instruction": (
                    f"Use VRT category '{result['vrt_category']}' (P{result['priority']}, "
                    f"{result['priority_label']}) for this finding. "
                    f"Match confidence: {result['confidence']:.0%} via {result['match_method']}."
                ),
            },
            indent=2,
        )

    # Otherwise, search the taxonomy
    results = vrt.search(query)
    if not results:
        return json.dumps(
            {
                "results": [],
                "message": f"No VRT entries found for '{query}'. Try different keywords.",
            }
        )

    return json.dumps(
        {
            "results": results,
            "count": len(results),
            "instruction": "Pick the most specific matching category from the results above.",
        },
        indent=2,
    )
