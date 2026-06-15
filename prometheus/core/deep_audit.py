"""Deep Audit Engine for Prometheus.

Browser-based vulnerability testing that goes beyond curl GET/HEAD.
Handles Cloudflare-protected sites, SPA auth flows, differential
response analysis, and automated PoC generation.

DESIGN PRINCIPLE: Agnostic. No platform-specific logic. The module
provides reusable audit PATTERNS that work on any target. The agent
chooses which patterns to apply based on what it discovers.

Audit patterns:
1. Differential Response Analysis - send variations, compare responses
2. Auth Flow Mapping - trace login/signup/SSO flows via browser
3. API Endpoint Discovery - intercept SPA network traffic
4. Rate Limit Probing - test for rate limiting on sensitive endpoints
5. Response Fingerprinting - create unique signatures for response types
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ResponseFingerprint:
    """Unique signature for an HTTP response."""

    status_code: int
    body_hash: str
    body_length: int
    content_type: str
    redirect_url: str
    headers: dict[str, str]
    body_snippet: str  # First 500 chars

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "body_hash": self.body_hash,
            "body_length": self.body_length,
            "content_type": self.content_type,
            "redirect_url": self.redirect_url,
            "body_snippet": self.body_snippet,
        }


@dataclass
class DifferentialResult:
    """Result of comparing multiple response fingerprints."""

    endpoint: str
    test_values: list[str]
    fingerprints: list[ResponseFingerprint]
    distinct_responses: int
    is_differential: bool
    response_classes: dict[str, list[str]]  # fingerprint_hash -> [test_values]
    verdict: str  # 'differential_confirmed', 'uniform', 'ambiguous'
    confidence: float
    evidence: str


@dataclass
class AuthFlowStep:
    """A single step in an authentication flow."""

    url: str
    method: str
    status_code: int
    request_body: str
    response_body_snippet: str
    redirect_url: str
    timestamp: float


@dataclass
class AuthFlowResult:
    """Complete auth flow trace."""

    target_url: str
    steps: list[AuthFlowStep]
    endpoints_discovered: list[str]
    api_calls: list[dict[str, Any]]  # {url, method, body, response_status, response_body}
    sso_redirects: list[str]
    error_responses: list[dict[str, Any]]


@dataclass
class RateLimitResult:
    """Result of rate limit probing."""

    endpoint: str
    requests_made: int
    requests_per_second: float
    limited: bool
    limit_threshold: int | None  # Requests before limit kicked in
    limit_response_code: int | None
    limit_response_body: str
    retry_after: str | None
    verdict: str  # 'no_limit', 'limited', 'soft_limit', 'hard_limit'
    confidence: float


# ---------------------------------------------------------------------------
# Response fingerprinting
# ---------------------------------------------------------------------------


def fingerprint_response(
    status_code: int,
    body: str,
    headers: dict[str, str],
    redirect_url: str = "",
) -> ResponseFingerprint:
    """Create a unique fingerprint for an HTTP response.

    The fingerprint captures the essential characteristics that distinguish
    one response type from another, ignoring non-deterministic fields.
    """
    # Hash the body but strip timestamps, request IDs, nonces
    cleaned_body = _normalize_body(body)
    body_hash = hashlib.sha256(cleaned_body.encode()).hexdigest()[:16]

    content_type = headers.get("content-type", "")

    return ResponseFingerprint(
        status_code=status_code,
        body_hash=body_hash,
        body_length=len(body),
        content_type=content_type,
        redirect_url=redirect_url,
        headers=headers,
        body_snippet=body[:500],
    )


def _normalize_body(body: str) -> str:
    """Strip non-deterministic content from response body for hashing."""
    # Remove timestamps (ISO 8601, Unix timestamps, etc.)
    normalized = re.sub(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?",
        "<TIMESTAMP>",
        body,
    )
    normalized = re.sub(r"\b\d{10,13}\b", "<EPOCH>", normalized)
    # Remove UUIDs
    normalized = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "<UUID>",
        normalized,
        flags=re.IGNORECASE,
    )
    # Remove request IDs / trace IDs
    normalized = re.sub(
        r'"(?:request_id|trace_id|requestId|traceId|correlation_id)"\s*:\s*"[^"]*"',
        '"request_id":"<ID>"',
        normalized,
    )
    return normalized


def classify_responses(
    fingerprints: list[ResponseFingerprint],
    test_values: list[str],
) -> dict[str, list[str]]:
    """Group test values by their response fingerprint.

    Returns a dict mapping fingerprint_hash -> list of test values
    that produced that response. If multiple distinct fingerprints exist,
    the endpoint exhibits differential behavior.
    """
    classes: dict[str, list[str]] = {}
    for i, fp in enumerate(fingerprints):
        # Create a class key from status code + body hash
        # Include status code in the key so 400 and 200 are different classes
        # even if body hashes collide
        key = f"{fp.status_code}:{fp.body_hash}"
        if key not in classes:
            classes[key] = []
        if i < len(test_values):
            classes[key].append(test_values[i])
    return classes


# ---------------------------------------------------------------------------
# Differential response analysis
# ---------------------------------------------------------------------------


def analyze_differential(
    endpoint: str,
    test_values: list[str],
    fingerprints: list[ResponseFingerprint],
) -> DifferentialResult:
    """Analyze whether an endpoint returns different responses for different inputs.

    This is the core detection engine for:
    - Account enumeration (different response for existing vs non-existing accounts)
    - IDOR probing (different response for different resource IDs)
    - Parameter tampering (different response for different parameter values)
    """
    if len(fingerprints) != len(test_values):
        return DifferentialResult(
            endpoint=endpoint,
            test_values=test_values,
            fingerprints=fingerprints,
            distinct_responses=0,
            is_differential=False,
            response_classes={},
            verdict="error",
            confidence=0.0,
            evidence=f"Mismatch: {len(test_values)} test values but {len(fingerprints)} fingerprints",
        )

    classes = classify_responses(fingerprints, test_values)
    distinct = len(classes)

    if distinct <= 1:
        return DifferentialResult(
            endpoint=endpoint,
            test_values=test_values,
            fingerprints=fingerprints,
            distinct_responses=1,
            is_differential=False,
            response_classes=classes,
            verdict="uniform",
            confidence=0.9,
            evidence="All inputs produced the same response",
        )

    # Build evidence
    evidence_lines = [f"Endpoint: {endpoint}", f"Distinct responses: {distinct}", ""]
    for i, (fp_key, values) in enumerate(classes.items(), 1):
        status = fp_key.split(":")[0]
        evidence_lines.append(f"Response class {i}: HTTP {status}")
        evidence_lines.append(f"  Test values: {values}")
        evidence_lines.append(f"  Body hash: {fp_key}")
        # Find the matching fingerprint for a snippet
        for fp in fingerprints:
            if f"{fp.status_code}:{fp.body_hash}" == fp_key:
                evidence_lines.append(f"  Body snippet: {fp.body_snippet[:200]}")
                if fp.redirect_url:
                    evidence_lines.append(f"  Redirect: {fp.redirect_url}")
                break
        evidence_lines.append("")

    # Check for specific vulnerability patterns
    verdict = _classify_differential_type(fingerprints, classes)

    return DifferentialResult(
        endpoint=endpoint,
        test_values=test_values,
        fingerprints=fingerprints,
        distinct_responses=distinct,
        is_differential=True,
        response_classes=classes,
        verdict=verdict,
        confidence=0.85 if distinct >= 3 else 0.7,
        evidence="\n".join(evidence_lines),
    )


def _classify_differential_type(
    fingerprints: list[ResponseFingerprint],
    classes: dict[str, list[str]],
) -> str:
    """Classify the type of differential response detected."""
    statuses = set(fp.status_code for fp in fingerprints)
    has_redirect = any(fp.redirect_url for fp in fingerprints)
    has_error = any(fp.status_code >= 400 for fp in fingerprints)

    # Account enumeration: mix of error (nonexistent) and success/redirect (existing)
    if has_error and (200 in statuses or has_redirect):
        if has_redirect:
            redirect_urls = [fp.redirect_url for fp in fingerprints if fp.redirect_url]
            if any(
                "saml" in u.lower() or "sso" in u.lower() or "oauth" in u.lower()
                for u in redirect_urls
            ):
                return "account_enumeration_with_sso"
        return "account_enumeration"

    # Status code differences without clear pattern
    if len(statuses) >= 2:
        return "differential_status_codes"

    # Same status but different body content
    return "differential_body_content"


# ---------------------------------------------------------------------------
# Auth flow tracing (browser-based)
# ---------------------------------------------------------------------------


def build_auth_flow_trace_script(
    login_url: str,
    email: str,
    password: str = "test_password_123",
) -> str:
    """Generate a Python script that traces an auth flow via browser-harness.

    The script:
    1. Navigates to the login page
    2. Submits the email
    3. Captures all network requests made during the flow
    4. Returns the trace as JSON

    Returns: Python script code that can be executed in the sandbox.
    """
    return f'''
import json
import time
import sys
sys.path.insert(0, "/opt/browser-harness/src")

from bu import BrowserUse

def trace_auth_flow():
    """Trace the authentication flow for a given email."""
    bu = BrowserUse(cdp_url="http://127.0.0.1:9222")
    page = bu.page

    api_calls = []
    redirects = []

    # Monitor network traffic
    def on_response(response):
        try:
            url = response.url
            status = response.status
            req = response.request
            body_text = ""
            try:
                body_text = response.text()[:1000]
            except:
                pass

            api_calls.append({{
                "url": url,
                "method": req.method,
                "status": status,
                "request_body": req.post_data[:500] if req.post_data else "",
                "response_body": body_text,
                "headers": dict(req.headers),
            }})
        except Exception as e:
            pass

    page.on("response", on_response)

    # Navigate to login page
    print(f"Navigating to {login_url}")
    page.goto("{login_url}", wait_until="networkidle", timeout=30000)
    time.sleep(2)

    # Find and fill email field
    email_selectors = [
        'input[type="email"]',
        'input[name="email"]',
        'input[name="username"]',
        'input[placeholder*="email" i]',
        'input[placeholder*="user" i]',
        'input[type="text"]',
    ]

    email_filled = False
    for selector in email_selectors:
        try:
            el = page.query_selector(selector)
            if el:
                el.fill("{email}")
                email_filled = True
                print(f"Filled email via {{selector}}")
                break
        except:
            continue

    if not email_filled:
        print("WARNING: Could not find email input field")

    # Find and click submit/continue button
    submit_selectors = [
        'button[type="submit"]',
        'button:has-text("Continue")',
        'button:has-text("Sign in")',
        'button:has-text("Log in")',
        'button:has-text("Next")',
        'input[type="submit"]',
    ]

    submitted = False
    for selector in submit_selectors:
        try:
            el = page.query_selector(selector)
            if el and el.is_visible():
                el.click()
                submitted = True
                print(f"Clicked submit via {{selector}}")
                break
        except:
            continue

    if not submitted:
        print("WARNING: Could not find submit button")

    # Wait for navigation/response
    time.sleep(5)
    page.wait_for_load_state("networkidle", timeout=15000)

    final_url = page.url
    print(f"Final URL: {{final_url}}")

    # Capture page content
    page_content = page.content()[:2000]

    result = {{
        "initial_url": "{login_url}",
        "email": "{email}",
        "final_url": final_url,
        "api_calls": api_calls,
        "page_title": page.title(),
        "page_snippet": page_content[:500],
    }}

    print("\\n===TRACE_RESULT===")
    print(json.dumps(result, indent=2, default=str))
    print("===END_TRACE===")

    return result

if __name__ == "__main__":
    trace_auth_flow()
'''


# ---------------------------------------------------------------------------
# Rate limit probing
# ---------------------------------------------------------------------------


def analyze_rate_limit(
    endpoint: str,
    responses: list[dict[str, Any]],
    time_span_seconds: float,
) -> RateLimitResult:
    """Analyze a series of responses to determine if rate limiting exists.

    Args:
        endpoint: The URL that was tested
        responses: List of {status_code, body, headers} dicts
        time_span_seconds: Total time the test took

    Returns:
        RateLimitResult with verdict and confidence
    """
    if not responses:
        return RateLimitResult(
            endpoint=endpoint,
            requests_made=0,
            requests_per_second=0,
            limited=False,
            limit_threshold=None,
            limit_response_code=None,
            limit_response_body="",
            retry_after=None,
            verdict="no_data",
            confidence=0.0,
        )

    rps = len(responses) / max(time_span_seconds, 0.1)
    rate_limit_codes = {429, 503, 529}
    limit_idx = None
    limit_code = None
    limit_body = ""
    retry_after = None

    for i, resp in enumerate(responses):
        code = resp.get("status_code", 0)
        if code in rate_limit_codes:
            limit_idx = i
            limit_code = code
            limit_body = resp.get("body", "")[:500]
            retry_after = resp.get("headers", {}).get("retry-after")
            break

    if limit_idx is not None:
        if limit_idx <= 5:
            verdict = "hard_limit"
            confidence = 0.95
        elif limit_idx <= 20:
            verdict = "soft_limit"
            confidence = 0.85
        else:
            verdict = "soft_limit"
            confidence = 0.7
        return RateLimitResult(
            endpoint=endpoint,
            requests_made=len(responses),
            requests_per_second=rps,
            limited=True,
            limit_threshold=limit_idx,
            limit_response_code=limit_code,
            limit_response_body=limit_body,
            retry_after=retry_after,
            verdict=verdict,
            confidence=confidence,
        )

    return RateLimitResult(
        endpoint=endpoint,
        requests_made=len(responses),
        requests_per_second=rps,
        limited=False,
        limit_threshold=None,
        limit_response_code=None,
        limit_response_body="",
        retry_after=None,
        verdict="no_limit",
        confidence=min(0.7 + (len(responses) * 0.01), 0.95),
    )


# ---------------------------------------------------------------------------
# PoC generation
# ---------------------------------------------------------------------------


def generate_poc_script(
    finding_title: str,
    endpoint: str,
    method: str,
    request_body_template: str,
    test_cases: list[dict[str, Any]],
    differential_result: DifferentialResult | None = None,
) -> str:
    """Generate a verified PoC script from test results.

    Args:
        finding_title: Title of the vulnerability
        endpoint: The vulnerable endpoint URL
        method: HTTP method (GET, POST, etc.)
        request_body_template: Request body with {input} placeholder
        test_cases: List of {value, expected_status, description}
        differential_result: Optional pre-computed differential analysis

    Returns:
        Python PoC script as a string, ready to execute
    """
    test_cases_json = json.dumps(test_cases, indent=4)
    body_template_escaped = request_body_template.replace('"', '\\"')
    meta_json = json.dumps(
        {
            "endpoint": endpoint,
            "method": method,
            "body_template": request_body_template,
            "test_cases": test_cases,
        },
        default=str,
    )

    poc = f'''#!/usr/bin/env python3
"""
PoC: {finding_title}
Endpoint: {method} {endpoint}
Generated by Prometheus Deep Audit Engine
"""
# ===PROMETHEUS_META_BEGIN===
# {meta_json}
# ===PROMETHEUS_META_END===

import requests
import json
import sys

ENDPOINT = "{endpoint}"
METHOD = "{method}"
BODY_TEMPLATE = "{body_template_escaped}"

TEST_CASES = {test_cases_json}

def run_test(case):
    """Execute a single test case."""
    body = BODY_TEMPLATE.replace("{{input}}", case["value"])
    try:
        if METHOD.upper() == "POST":
            resp = requests.post(
                ENDPOINT,
                json=json.loads(body) if body.startswith("{{") else None,
                data=body if not body.startswith("{{") else None,
                headers={{"Content-Type": "application/json"}},
                timeout=15,
                allow_redirects=False,
            )
        else:
            resp = requests.get(
                ENDPOINT + "?" + body,
                timeout=15,
                allow_redirects=False,
            )

        return {{
            "value": case["value"],
            "description": case["description"],
            "status": resp.status_code,
            "body": resp.text[:500],
            "redirect": resp.headers.get("location", ""),
            "headers": dict(resp.headers),
        }}
    except Exception as e:
        return {{
            "value": case["value"],
            "description": case["description"],
            "status": 0,
            "body": str(e),
            "redirect": "",
            "headers": {{}},
        }}

def main():
    print("=" * 60)
    print(f"PoC: {finding_title}")
    print(f"Endpoint: {{METHOD}} {{ENDPOINT}}")
    print("=" * 60)

    results = []
    for i, case in enumerate(TEST_CASES, 1):
        print(f"\\n[{{i}}] Testing: {{case['description']}} (value={{case['value']}})")
        result = run_test(case)
        results.append(result)
        print(f"    Status: {{result['status']}}")
        if result["redirect"]:
            print(f"    Redirect: {{result['redirect'][:100]}}")
        print(f"    Body: {{result['body'][:200]}}")

    # Analyze results
    print("\\n" + "=" * 60)
    print("ANALYSIS")
    print("=" * 60)

    status_groups = {{}}
    for r in results:
        key = str(r["status"])
        if key not in status_groups:
            status_groups[key] = []
        status_groups[key].append(r["description"])

    distinct = len(status_groups)
    print(f"\\nDistinct response codes: {{distinct}}")

    for status, descriptions in status_groups.items():
        print(f"  HTTP {{status}}: {{descriptions}}")

    if distinct > 1:
        print("\\n[CONFIRMED] Differential responses detected!")
        print("The endpoint returns different responses based on input.")
        return 0
    else:
        print("\\n[NOT CONFIRMED] All responses were identical.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
'''
    return poc


# ---------------------------------------------------------------------------
# Report generation for bug bounty platforms
# ---------------------------------------------------------------------------


def generate_bugcrowd_report(
    title: str,
    target: str,
    endpoint: str,
    description: str,
    poc_steps: list[str],
    differential_result: DifferentialResult,
    remediation: list[str],
    cwe: str = "CWE-203",
    cvss_vector: str = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_score: float = 5.3,
) -> dict[str, str]:
    """Generate a bug bounty report from audit results.

    Returns dict with keys: summary, vrt_category, description, poc_code.
    Uses the Bugcrowd VRT classifier for accurate category mapping.
    """
    # Build the description
    desc_parts = [
        description,
        "",
        "## Affected Endpoint",
        "",
        f"```",
        f"{endpoint}",
        f"```",
        "",
        "## Proof of Concept",
        "",
    ]
    for i, step in enumerate(poc_steps, 1):
        desc_parts.append(f"{i}. {step}")

    desc_parts.extend(
        [
            "",
            "## Evidence",
            "",
            "The following distinct responses were observed:",
            "",
            "| Input | HTTP Status | Response |",
            "|-------|-------------|----------|",
        ]
    )

    for fp_key, values in differential_result.response_classes.items():
        status = fp_key.split(":")[0]
        for fp in differential_result.fingerprints:
            if f"{fp.status_code}:{fp.body_hash}" == fp_key:
                snippet = fp.body_snippet[:80].replace("|", "\\|")
                for v in values:
                    desc_parts.append(f"| {v[:30]} | {status} | {snippet} |")
                break

    desc_parts.extend(
        [
            "",
            f"Total distinct response classes: {differential_result.distinct_responses}",
            "",
            "## Classification",
            "",
            f"- CWE: {cwe}",
            f"- CVSS: {cvss_score} ({cvss_vector})",
            "",
            "## Remediation",
            "",
        ]
    )
    for i, fix in enumerate(remediation, 1):
        desc_parts.append(f"{i}. {fix}")

    description_text = "\n".join(desc_parts)

    # Use VRT classifier for accurate category mapping
    try:
        from prometheus.core.vrt_classifier import get_vrt_classifier

        vrt = get_vrt_classifier()
        classification = vrt.classify(
            title=title,
            description=description,
            cwe=cwe,
            endpoint=endpoint,
        )
        vrt_category = classification["vrt_category"]
        logger.info(
            "VRT classification: %s (priority=%s, confidence=%.2f, method=%s)",
            vrt_category,
            classification["priority"],
            classification["confidence"],
            classification["match_method"],
        )
    except Exception:
        logger.debug("VRT classifier unavailable, using fallback")
        vrt_category = "Unknown"

    return {
        "summary": title,
        "vrt_category": vrt_category,
        "description": description_text,
        "cwe": cwe,
        "cvss_vector": cvss_vector,
        "cvss_score": str(cvss_score),
    }


# ---------------------------------------------------------------------------
# Orchestrator: full deep audit pipeline
# ---------------------------------------------------------------------------


def build_deep_audit_plan(
    target_url: str,
    finding_hint: str = "",
) -> dict[str, Any]:
    """Generate an audit plan for a target.

    This is called by the agent to determine which audit patterns to apply.
    Returns a structured plan the agent can execute step by step.
    """
    phases: list[dict[str, Any]] = []

    # Phase 1: Auth flow mapping (if login detected)
    phases.append(
        {
            "name": "auth_flow_mapping",
            "description": "Navigate to login page via browser, trace auth flow, discover API endpoints",
            "tool": "browser-harness",
            "steps": [
                "Navigate to target login page",
                "Monitor network traffic for API calls",
                "Submit test email and capture request/response",
                "Document all discovered endpoints",
            ],
        }
    )

    # Phase 2: Differential response analysis
    phases.append(
        {
            "name": "differential_analysis",
            "description": "Test endpoint with varied inputs, compare response fingerprints",
            "tool": "curl_cffi or browser-harness",
            "steps": [
                "Identify the primary auth endpoint from Phase 1",
                "Send 3+ distinct test values (nonexistent, valid, SSO)",
                "Fingerprint each response (status, body hash, redirect)",
                "Classify responses and determine if differential",
            ],
        }
    )

    # Phase 3: Rate limit testing
    phases.append(
        {
            "name": "rate_limit_probing",
            "description": "Send rapid requests to check for rate limiting",
            "tool": "curl_cffi",
            "steps": [
                "Send 20+ rapid requests to the endpoint",
                "Track response codes over time",
                "Detect 429/503 responses or CAPTCHA challenges",
                "Calculate effective rate limit threshold",
            ],
        }
    )

    # Phase 4: PoC generation
    phases.append(
        {
            "name": "poc_generation",
            "description": "Generate executable PoC from collected evidence",
            "tool": "code generation",
            "steps": [
                "Build PoC script from test cases and responses",
                "Include real request/response evidence",
                "Generate submission-ready report",
            ],
        }
    )

    return {
        "target": target_url,
        "phases": phases,
    }
