"""``create_vulnerability_report`` — file a vuln finding with dedup + CVSS."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# Retry guard: prevent the agent from filing the same finding more than
# ``_MAX_RETRIES`` times in a single scan. Keyed by the NORMALISED
# title (whitespace-collapsed, lower-cased, prefix-trimmed) so a
# cosmetic re-write ("X" vs "X Discloses …") still hits the guard.
# The scan-id scopes the counter so resumed scans don't inherit stale
# counts from earlier runs.
import threading as _threading

_MAX_RETRIES = 2  # block on the 3rd attempt — the 1st attempt and 1 retry are tolerated
_RETRY_GUARD_LOCK = _threading.Lock()
_retry_counters: dict[tuple[str, str, str], int] = {}


def _normalise_title_for_dedup(title: str) -> str:
    """Collapse whitespace, lower-case, and strip a leading 'Test '/ 'Test: ' prefix.

    Why this matters: the LaunchDarkly scan logged nine ``create_vulnerability_report``
    calls for the same underlying GraphQL finding, where the title only changed by
    trailing punctuation, leading "Test ", or re-ordering of the noun phrase.
    A raw SHA-256 hash let all of those through because the bytes differed.
    """
    if not title:
        return ""
    t = " ".join(str(title).split()).strip().lower()
    # Strip a leading "test" / "test:" placeholder prefix (case-insensitive
    # above already lower-cased the string).
    for prefix in ("test: ", "test ", "fuzz: ", "fuzz "):
        if t.startswith(prefix):
            t = t[len(prefix) :]
            break
    # Drop trailing punctuation the LLM adds/omits between attempts.
    return t.rstrip(" .!?:;")


def _check_retry_guard(title: str, endpoint: str, scan_id: str | None = None) -> str | None:
    """Increment retry counter; return error message if exceeded.

    Returns the rejection string when the agent has attempted the same
    normalised title more than ``_MAX_RETRIES`` times for this scan
    (default scan scope if ``scan_id`` is not provided).

    The counter is shared across agents within the same scan by design:
    if the agent loop hits the same finding from a child agent, the
    cap still fires.
    """
    normalised = _normalise_title_for_dedup(title)
    key = (scan_id or "_default", normalised, endpoint or "")
    with _RETRY_GUARD_LOCK:
        count = _retry_counters.get(key, 0) + 1
        _retry_counters[key] = count
    if count > _MAX_RETRIES:
        logger.warning(
            "create_vulnerability_report: BLOCKED '%s' on %s after %d attempts "
            "(scan=%s) — stop retrying this finding.",
            title,
            endpoint or "(no endpoint)",
            count,
            scan_id or "_default",
        )
        return (
            f"RETRY LIMIT EXCEEDED: You have attempted to file a finding titled "
            f"'{title}' {count} times in this scan (normalised: '{normalised}'). "
            f"Stop retrying. Either fix the validation issues, change your "
            f"approach, or move on to other findings."
        )
    if count > 1:
        logger.warning(
            "create_vulnerability_report: Retry %d/%d for '%s' on %s (scan=%s) "
            "— will block on attempt %d",
            count,
            _MAX_RETRIES,
            title,
            endpoint or "(no endpoint)",
            scan_id or "_default",
            _MAX_RETRIES + 1,
        )
    return None


def reset_retry_guard(scan_id: str | None = None) -> None:
    """Clear retry counters — used between scans or in tests."""
    with _RETRY_GUARD_LOCK:
        if scan_id is None:
            _retry_counters.clear()
            return
        prefix = f"{scan_id}\x00"
        for key in list(_retry_counters.keys()):
            if key[0] == scan_id or key[0].startswith(prefix):
                _retry_counters.pop(key, None)


def _detect_bugcrowd_target(target: str) -> bool:
    """Check if a target is a Bugcrowd program.

    Detection methods:
    1. Target URL host is bugcrowd.com or a subdomain of it
    2. Target is registered in the target registry with platform=bugcrowd
    """
    if not target:
        return False
    from urllib.parse import urlparse

    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.netloc or "").lower()
    if host == "bugcrowd.com" or host.endswith(".bugcrowd.com"):
        return True
    # Check target registry
    try:
        from prometheus.core.target_registry import TargetRegistry

        reg = TargetRegistry()
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.netloc or parsed.path.split("/")[0]
        for t in reg.list_targets():
            if t.get("domain") == domain:
                config = t.get("target_config") or {}
                if isinstance(config, str):
                    import json as _json

                    try:
                        config = _json.loads(config)
                    except Exception:
                        config = {}
                if config.get("platform") == "bugcrowd":
                    return True
    except Exception:
        logger.debug("platform detection failed, returning False", exc_info=True)
    return False


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


_CODE_LOCATION_FIELDS = (
    "file",
    "start_line",
    "end_line",
    "snippet",
    "label",
    "fix_before",
    "fix_after",
)


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty. Use a relative path from the repo root (e.g., 'src/app.py')."
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'. Remove the leading '/'."
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'. Use a path relative to the repo root."
    return None


def _normalize_code_locations(
    raw: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    cleaned: list[dict[str, Any]] = []
    for loc in raw:
        normalized: dict[str, Any] = {}
        for field in _CODE_LOCATION_FIELDS:
            if field not in loc or loc[field] is None:
                continue
            value = loc[field]
            if field in ("start_line", "end_line"):
                try:
                    normalized[field] = int(value)
                except (TypeError, ValueError):
                    continue
            else:
                text = (
                    str(value).strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else str(value).strip()
                )
                if text:
                    normalized[field] = text
        if normalized.get("file") and normalized.get("start_line") is not None:
            cleaned.append(normalized)
    return cleaned or None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(
                f"REJECTED: code_locations[{i}]: {path_err}. Use a relative path from the repo root (e.g., 'src/app.py')."
            )
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(
                f"REJECTED: code_locations[{i}]: start_line must be a positive integer, got '{start}'."
            )
        end = loc.get("end_line")
        if end is None:
            errors.append(f"REJECTED: code_locations[{i}]: end_line is required.")
        elif not isinstance(end, int) or end < 1:
            errors.append(
                f"REJECTED: code_locations[{i}]: end_line must be a positive integer, got '{end}'."
            )
        elif isinstance(start, int) and end < start:
            errors.append(
                f"REJECTED: code_locations[{i}]: end_line ({end}) must be >= start_line ({start})."
            )
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"REJECTED: Invalid CVE format: '{cve}'. Must match 'CVE-YYYY-NNNNN' (e.g., 'CVE-2024-12345'). If unsure, omit the cve field entirely."
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"REJECTED: Invalid CWE format: '{cwe}'. Must match 'CWE-NNN' (e.g., 'CWE-89' for SQL Injection). Use the most specific child CWE."
    return None


def _calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
            f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
            f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
            f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
        )
        c = CVSS3(vector)
        score = c.scores()[0]
        severity = c.severities()[0].lower()
    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "REJECTED: Title cannot be empty. Use a specific title like 'SQL Injection in /api/users login parameter'.",
    "description": "REJECTED: Description cannot be empty. Explain how the vulnerability was discovered and what it is.",
    "impact": "REJECTED: Impact cannot be empty. Describe what an attacker can achieve (e.g., 'Access any user's account by resetting their password').",
    "target": "REJECTED: Target cannot be empty. Provide the affected URL, domain, or repository.",
    "technical_analysis": "REJECTED: Technical analysis cannot be empty. Explain the root cause and exploitation mechanism.",
    "poc_description": "REJECTED: PoC description cannot be empty. Provide step-by-step reproduction instructions with exact URLs, headers, and payloads.",
    "poc_script_code": "REJECTED: PoC script/code is REQUIRED. Provide actual exploit code (curl commands, Python script, or raw HTTP requests), not a description.",
    "remediation_steps": "REJECTED: Remediation steps cannot be empty. Provide a specific, actionable fix for the vulnerability.",
}

_MIN_POC_DESCRIPTION_LEN = 50
_MIN_POC_CODE_LEN = 30
_THEORETICAL_PATTERNS = [
    "could allow",
    "could potentially",
    "may lead to",
    "might be possible",
    "an attacker could theoretically",
    "this could be exploited",
    "potential vulnerability",
    "if an attacker were to",
]


def _count_passed_controls(controls: list[dict[str, Any]] | None) -> int:
    if not controls:
        return 0
    return sum(1 for item in controls if item.get("passed") is not False)


def _validate_report_control_gate(
    *,
    hypothesis_id: str | None,
    positive_controls: list[dict[str, Any]] | None,
    negative_controls: list[dict[str, Any]] | None,
    validation_agent_id: str | None,
    poc_description: str = "",
    poc_script_code: str = "",
) -> list[str]:
    """Require a validated hypothesis or explicit control evidence.

    When the finding has concrete PoC evidence (curl commands, script code,
    HTTP request/response dumps), the control gate defers to the later
    PoC validation step instead of blocking early.
    """

    if hypothesis_id:
        try:
            from prometheus.core.hypotheses import get_active_hypothesis_manager

            manager = get_active_hypothesis_manager()
            if manager is None:
                return [
                    "REPORT VALIDATION GATE BLOCKED: hypothesis_id was provided but "
                    "the active HypothesisManager is not initialized."
                ]
            gate = manager.report_gate(hypothesis_id)
        except Exception as exc:
            return [f"REPORT VALIDATION GATE BLOCKED: could not verify hypothesis_id: {exc}"]
        if not gate.allowed:
            return [
                "REPORT VALIDATION GATE BLOCKED: hypothesis_id must reference a validated hypothesis. "
                f"Status={gate.status}; missing={', '.join(gate.missing)}"
            ]
        return []

    errors: list[str] = []
    positives = _count_passed_controls(positive_controls)
    negatives = _count_passed_controls(negative_controls)

    # If the PoC contains concrete exploit code, defer to PoC validation
    # instead of requiring hypothesis/controls up front.
    _poc_text = f"{poc_description or ''} {poc_script_code or ''}".lower()
    _has_concrete_poc = any(
        keyword in _poc_text
        for keyword in [
            "curl ",
            "wget ",
            "python ",
            "import requests",
            "fetch(",
            "http",
            "POST ",
            "GET ",
            "Authorization:",
            "Content-Type:",
            "<script",
            "alert(",
            "onerror=",
            "document.cookie",
            "response",
            "request",
            "payload",
        ]
    )

    if _has_concrete_poc:
        # Defer to PoC validation — the finding has executable evidence.
        # Only require the validation agent if controls are completely absent.
        if positives == 0 and negatives == 0 and not validation_agent_id:
            errors.append(
                "CONTROL GATE SOFT BLOCK: no hypothesis or controls provided. "
                "Concrete PoC detected — will rely on PoC validation and live verification. "
                "Consider spawning a validation sub-agent for independent confirmation."
            )
        return []  # Soft block — let PoC validation decide

    if positives < 2 or negatives < 1:
        errors.append(
            "REPORT VALIDATION GATE BLOCKED: provide a validated hypothesis_id or explicit "
            "control evidence. Required: at least two passed positive controls and one passed "
            f"negative control. Got positive_controls={positives}, negative_controls={negatives}."
        )
    if not validation_agent_id:
        errors.append(
            "REPORT VALIDATION GATE BLOCKED: validation_agent_id is required unless a "
            "validated hypothesis_id is supplied. Independent validation must be attached."
        )
    return errors


async def _do_create(  # noqa: PLR0912
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: list[dict[str, Any]] | None,
    hypothesis_id: str | None = None,
    positive_controls: list[dict[str, Any]] | None = None,
    negative_controls: list[dict[str, Any]] | None = None,
    validation_agent_id: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    # Retry guard: prevent the agent from filing the same finding more than
    # ``_MAX_RETRIES`` times. Keys on the NORMALISED title + scan id so
    # cosmetic re-writes still trip the guard.
    retry_error = _check_retry_guard(title, endpoint or "", scan_id=scan_id)
    if retry_error:
        return {"success": False, "error": retry_error, "title": title}

    errors: list[str] = []
    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
    }
    for name, msg in _REQUIRED_FIELDS.items():
        if not str(fields.get(name) or "").strip():
            errors.append(msg)

    errors.extend(
        _validate_report_control_gate(
            hypothesis_id=hypothesis_id,
            positive_controls=positive_controls,
            negative_controls=negative_controls,
            validation_agent_id=validation_agent_id,
            poc_description=poc_description or "",
            poc_script_code=poc_script_code or "",
        ),
    )

    # BLOCK test/placeholder content — the LLM sometimes generates filler text
    # to pass minimum character requirements instead of real findings
    _placeholder_patterns = [
        r"test\s+(description|impact|analysis|poc|technical)\s+that\s+is\s+long\s+enough",
        r"test\s+(description|impact|analysis|poc|technical)\s+that\s+demonstrates",
        r"^test\s+header\s+issue$",
        r"fix\s+the\s+header$",
        r"test\s+(description|impact|analysis)\s+of\s+the\s+(vulnerability|issue|finding)",
    ]
    for field_name in [
        "title",
        "description",
        "impact",
        "technical_analysis",
        "poc_description",
        "remediation_steps",
    ]:
        field_val = str(fields.get(field_name) or "").strip().lower()
        for pat in _placeholder_patterns:
            if re.search(pat, field_val):
                errors.append(
                    f"REJECTED: '{field_name}' contains placeholder/test content (matched: '{pat}'). "
                    "This appears to be generated filler text, not a real finding. "
                    "Replace with actual vulnerability evidence: real HTTP requests, "
                    "real responses, and a real attack demonstration."
                )
                break

    # PoC quality gates — reject theoretical/empty proofs
    poc_desc = str(fields.get("poc_description") or "").strip()
    poc_code = str(fields.get("poc_script_code") or "").strip()

    if poc_desc and len(poc_desc) < _MIN_POC_DESCRIPTION_LEN:
        errors.append(
            f"REJECTED: poc_description is too short ({len(poc_desc)} chars, minimum {_MIN_POC_DESCRIPTION_LEN}). "
            "Add detailed step-by-step reproduction instructions including: "
            "exact URLs, HTTP headers, request bodies, and expected responses."
        )

    if poc_code and len(poc_code) < _MIN_POC_CODE_LEN:
        errors.append(
            f"REJECTED: poc_script_code is too short ({len(poc_code)} chars, minimum {_MIN_POC_CODE_LEN}). "
            "Add actual exploit code: curl commands with full headers, Python scripts using requests/httpx, "
            "or raw HTTP request/response dumps showing the vulnerability."
        )

    # Reject theoretical-only PoC descriptions
    poc_lower = poc_desc.lower()
    for pattern in _THEORETICAL_PATTERNS:
        if pattern in poc_lower:
            errors.append(
                f"REJECTED: Theoretical language detected in poc_description ('{pattern}'). "
                "Replace with concrete, past-tense evidence: 'I sent X request and received Y response, "
                "which proves Z is exploitable.' Avoid 'could', 'may', 'might' — describe what you "
                "ACTUALLY did, not what could theoretically be done."
            )
            break

    # Reject PoC code that looks like prose, not code
    if poc_code and not any(
        c in poc_code
        for c in [
            "curl ",
            "python",
            "import ",
            "requests.",
            "http",
            "fetch(",
            "$(",
            "POST ",
            "GET ",
            "Authorization:",
            "Content-Type:",
            "exec",
            "subprocess",
            "payload",
            '{"',
            "httpx",
            "burp",
        ]
    ):
        errors.append(
            "REJECTED: poc_script_code does not appear to contain actual exploit code. "
            "The code must contain recognizable commands (curl, Python requests, fetch(), etc.). "
            'Example valid PoC: \'curl -X POST https://target.com/api/login -d {"user":"admin","pass":"\' OR 1=1--"}\'. '
            "Do not put descriptions in the code field — put them in poc_description."
        )

    # HackerOne standard: reject missing-header reports that only show curl -I
    # without demonstrating the attack the missing header would prevent
    title_lower = (title or "").lower()
    if (
        "missing" in title_lower
        and "header" in title_lower
        and poc_code
        and re.search(r"curl\s.*-[a-zA-Z]*I", poc_code)
        and not any(
            kw in poc_desc.lower()
            for kw in [
                "iframe",
                "clickjack",
                "embed",
                "attack",
                "exploit",
                "steal",
                "hijack",
                "inject",
                "exfiltrat",
            ]
        )
    ):
        errors.append(
            "REJECTED: Missing-header finding with only 'curl -I' output. "
            "Your PoC shows the header is missing but does NOT demonstrate an attack. "
            "To fix: (1) Show an actual exploit — e.g., for missing X-Frame-Options, "
            "embed the page in an iframe and demonstrate clickjacking on a sensitive action. "
            "For missing CSP, inject a <script> tag and show it executes. "
            "(2) The poc_description must explain the attack scenario, not just list missing headers. "
            "Per HackerOne standards, missing headers without demonstrated impact are Informational only."
        )

    # REPUTATION GUARD: block header/config findings without demonstrated exploitation
    # These get closed as "Not Applicable" on HackerOne, damaging submitter reputation
    _header_config_patterns = [
        "missing.*header",
        "missing.*policy",
        "missing.*isolation",
        "weak.*hsts",
        "weak.*strict",
        "allows.*unsafe-inline",
        "allows.*unsafe-eval",
        "deprecated.*header",
        "insecure.*cookie",
        "missing.*httponly",
        "missing.*secure.*flag",
        "missing.*samesite",
        "csp.*allows",
        "csp.*weak",
        "csp.*bypass",
        "header.*enables",
        "header.*allows",
        "misconfigured.*header",
    ]
    _is_header_finding = any(re.search(pat, title_lower) for pat in _header_config_patterns)
    # Also check description and impact — LLM uses generic titles to bypass title-only guard
    _all_text_lower = f"{title_lower} {(description or '').lower()} {(impact or '').lower()} {(technical_analysis or '').lower()}"
    if not _is_header_finding:
        _is_header_finding = any(re.search(pat, _all_text_lower) for pat in _header_config_patterns)

    if _is_header_finding:
        # Require demonstrated exploitation, not just header analysis
        poc_desc_lower = poc_desc.lower()
        poc_code_lower = poc_code.lower()
        _exploitation_indicators = [
            "injected",
            "executed",
            "stole",
            "extracted",
            "hijacked",
            "bypassed",
            "accessed",
            "modified",
            "created.*account",
            "escalated",
            "achieved",
            "demonstrated",
            "proof.*xss",
            "alert(",
            "document.cookie",
            "document.domain",
            "payload.*executed",
            "script.*injected",
            "iframe.*load",
            "successfully.*exploit",
        ]
        _has_exploitation = any(
            re.search(ind, poc_desc_lower) or re.search(ind, poc_code_lower)
            for ind in _exploitation_indicators
        )
        # Also check for actual HTTP evidence (request+response showing the attack)
        _has_http_evidence = any(
            kw in poc_desc_lower
            for kw in ["http/", "status 200", "status 30", "response body", "response header"]
        )

        if not _has_exploitation and not _has_http_evidence:
            errors.append(
                "REPUTATION GUARD BLOCKED: This is a header/configuration finding without demonstrated exploitation. "
                "The PoC only analyzes headers but does not show a concrete attack. "
                "To fix: (1) Demonstrate the actual attack the misconfiguration enables — "
                "inject a script, steal a cookie, bypass a restriction, or hijack a session. "
                "(2) Include HTTP request/response evidence of the attack succeeding. "
                "(3) Replace theoretical language ('could allow') with concrete proof ('injected <script>alert(1)</script> which executed'). "
                "HackerOne programs reject header-only findings as 'Not Applicable', damaging your reputation."
            )

    # VERSION DISCLOSURE / FINGERPRINTING GUARD: block findings that only
    # disclose technology versions without demonstrating an exploitable vulnerability.
    # "Server header reveals nginx/1.24.0" is reconnaissance, not a vuln.
    _version_disclosure_patterns = [
        "version.*disclos",
        "banner.*disclos",
        "nginx.*version",
        "apache.*version",
        "server.*header.*reveal",
        "x-powered-by",
        "technology.*fingerprint",
        "framework.*version.*detect",
        "version.*information",
        "disclos.*version",
    ]
    _is_version_disclosure = any(
        re.search(pat, title_lower) for pat in _version_disclosure_patterns
    )
    if not _is_version_disclosure:
        _is_version_disclosure = any(
            re.search(pat, _all_text_lower) for pat in _version_disclosure_patterns
        )

    if _is_version_disclosure:
        # Require exploitation of a specific CVE, not just version observation
        _exploit_indicators_version = [
            "exploit.*cve",
            "cve.*exploit",
            "metasploit",
            "exploit-db",
            "poc.*exploit",
            "used.*to.*gain.*access",
            "rce.*confirmed",
            "shell.*obtained",
            "code.*execution",
            "command.*execution",
            "sql.*injection.*confirmed",
            "xss.*confirmed",
            "successfully.*exploited.*version",
            "executed.*payload",
            "reverse.*shell",
        ]
        # Filter out negations — "no known CVEs are exploitable" is NOT exploitation evidence
        _negation_patterns = [
            "no.*known.*cve",
            "no.*critical.*cve",
            "not.*exploitable",
            "was.*not.*exploit",
            "could not.*exploit",
            "unable.*to.*exploit",
            "no.*exploitation",
            "no.*active.*exploit",
        ]
        _has_version_exploit = any(
            re.search(ind, _all_text_lower) for ind in _exploit_indicators_version
        )
        if _has_version_exploit:
            # Check if the exploit indicators appear in negated context
            for neg in _negation_patterns:
                # If a negation overlaps with any exploit indicator match, cancel it
                neg_match = re.search(neg, _all_text_lower)
                if neg_match:
                    for ind in _exploit_indicators_version:
                        exp_match = re.search(ind, _all_text_lower)
                        if exp_match and abs(exp_match.start() - neg_match.start()) < 200:
                            _has_version_exploit = False
                            break
                if not _has_version_exploit:
                    break
        if not _has_version_exploit:
            errors.append(
                "VERSION DISCLOSURE BLOCKED: This finding discloses a technology version "
                "but does NOT demonstrate exploiting a specific vulnerability in that version. "
                "Version disclosure is reconnaissance, not a vulnerability. "
                "To fix: (1) Identify a specific CVE in the disclosed version. "
                "(2) Build and execute a working PoC that exploits that CVE against the target. "
                "(3) Include HTTP request/response evidence of successful exploitation. "
                "Simply observing a version string in a response header is NOT reportable. "
                "HackerOne programs close version disclosure reports as 'Informational' or 'Not Applicable'."
            )

    # OBSERVATION VS EXPLOITATION GUARD: reject findings where the PoC only
    # shows a misconfiguration EXISTS but doesn't demonstrate it ENABLES an attack.
    # "The CORS header reflects any origin" is observation.
    # "The browser allows JS to read the response body cross-origin" is exploitation.
    # The PoC must cross the bridge from "this is misconfigured" to "this is exploitable."
    desc_text_early = (description or "").strip().lower()
    _observation_patterns = [
        (
            r"cors",
            [
                "response body",
                "read.*response",
                "exfil",
                "stole",
                "extracted",
                "readable",
                "cross.origin.*read",
                "accessed.*data",
                "cookie.*sent",
                "credentials.*included",
                "token.*stolen",
                "client_id.*read",
                "auth.*code",
                # Origin reflected + credentials enabled = exploitation proof
                "allow.credentials.*true.*origin.*reflect",
                "origin.*reflect.*allow.credentials.*true",
                "credentials.*true.*reflected",
                "reflected.*credentials.*true",
                "response.*length.*bytes",
                "body.*length.*bytes",
                "email.*enumerat.*origin.*reflect",
            ],
        ),
        (
            r"misconfiguration",
            [
                "exploit",
                "bypass",
                "access",
                "stole",
                "extracted",
                "read.*data",
                "demonstrated",
                "proof",
                "successfully",
            ],
        ),
        (
            r"reflect",
            [
                "read.*body",
                "response.*readable",
                "exfil",
                "stole",
                "data.*access",
            ],
        ),
    ]
    for misconfig_keyword, required_exploit_evidence in _observation_patterns:
        if re.search(misconfig_keyword, title_lower) or re.search(
            misconfig_keyword, desc_text_early
        ):
            # Skip observation-only gate for XSS/script-injection findings —
            # these are inherently exploitable, not just configuration observations
            if misconfig_keyword == "reflect" and (
                "xss" in title_lower
                or "cross-site" in title_lower
                or "script" in title_lower
                or "javascript" in title_lower
                or "injection" in title_lower
                or "xss" in desc_text_early
                or "script" in desc_text_early
            ):
                continue
            _all_poc_text = f"{poc_desc.lower()} {poc_code.lower()} {technical_analysis.lower()}"
            has_exploit_evidence = any(
                re.search(ev, _all_poc_text) for ev in required_exploit_evidence
            )
            if not has_exploit_evidence:
                errors.append(
                    f"OBSERVATION-ONLY BLOCKED: Your finding describes a '{misconfig_keyword}' "
                    f"misconfiguration but only proves it EXISTS — not that it's EXPLOITABLE. "
                    f"To fix: Show the ACTUAL attack outcome. For example, if you found "
                    f"CORS reflects any origin, add a fetch() PoC that reads the response body "
                    f"and extracts sensitive data. 'The header reflects any origin' is reconnaissance. "
                    f"'The browser allowed JS to read the response body and extract the auth token' "
                    f"is a vulnerability. Provide the specific data you accessed or action you performed."
                )
                break

    # CORS-specific guard: CORS findings require proof that the reflected origin
    # actually enables reading response data or performing unauthorized actions
    if re.search(r"cors", title_lower) or re.search(r"cors", desc_text_early):
        _cors_exploit_indicators = [
            "read.*response",
            "response.*body",
            "exfil",
            "stole.*token",
            "extracted.*data",
            "accessed.*account",
            "read.*cookie",
            "document\\\\.cookie",
            "fetch.*response",
            "xhr.*response",
            "stole.*credential",
            "read.*secret",
            "accessed.*data",
            "cross.origin.*read",
            "bypassed.*sop",
            "same.origin.*bypass",
            # Origin reflected + credentials enabled = browser allows reading
            "allow.credentials.*true.*origin.*reflect",
            "origin.*reflect.*allow.credentials.*true",
            "credentials.*true.*reflected",
            "reflected.*credentials.*true",
            # Response body actually returned with evil origin
            "response.*length.*bytes",
            "body.*length.*bytes",
            "response.*readable.*evil",
            "body.*readable.*evil",
            # Combined ACAO + body evidence
            "origin.*reflected.*response.*body",
            "response.*body.*origin.*reflected",
            # Email enumeration via CORS
            "email.*enumerat.*origin.*reflect",
            "isEmailAvailable.*origin",
            # Preflight allows all methods + credentials
            "allow.methods.*allow.credentials",
        ]
        _all_text = f"{poc_desc.lower()} {poc_code.lower()} {technical_analysis.lower()}"
        _cors_has_exploit = any(re.search(p, _all_text) for p in _cors_exploit_indicators)
        if not _cors_has_exploit:
            errors.append(
                "CORS FINDING BLOCKED: Your PoC shows CORS headers reflect an origin, but does NOT prove "
                "the response body is readable cross-origin. To fix: (1) Write a JavaScript PoC using "
                "fetch() or XMLHttpRequest on an attacker-controlled domain that reads the API response body. "
                "(2) Show the actual data extracted from the response. "
                "(3) Many servers return different CORS headers on preflight vs actual requests — test the "
                "ACTUAL response, not just preflight. "
                "If you cannot read the response body cross-origin, the CORS misconfiguration has no "
                "security impact and should not be reported."
            )

    # Reject descriptions that are entirely theoretical with no concrete attack
    desc_text = (description or "").strip()
    desc_lower = desc_text.lower()

    # EXPLOIT VALIDATION: reject "I found" without "I used"
    # Discovery is recon. Exploitation is a vuln. The PoC must show USE, not just FIND.
    _discovery_only = [
        "found.*key",
        "found.*token",
        "found.*secret",
        "found.*credential",
        "discovered.*endpoint",
        "discovered.*parameter",
        "discovered.*key",
        "exposed.*key",
        "exposed.*token",
        "exposed.*secret",
        "leaked.*key",
        "leaked.*token",
        "leaked.*secret",
        "contains.*api.*key",
        "contains.*token",
        "contains.*secret",
        "hardcoded.*key",
        "hardcoded.*token",
        "hardcoded.*secret",
    ]
    _exploitation_proof = [
        "used.*to.*access",
        "called.*api",
        "read.*data",
        "extracted.*data",
        "retrieved.*document",
        "got.*response",
        "successfully.*authenticated",
        "bypassed.*auth",
        "elevated.*privilege",
        "accessed.*account",
        "modified.*data",
        "created.*account",
        "deleted.*resource",
    ]
    _is_discovery_only = any(re.search(p, desc_lower) for p in _discovery_only)
    _has_exploitation_proof = any(re.search(p, desc_lower) for p in _exploitation_proof)
    if _is_discovery_only and not _has_exploitation_proof:
        errors.append(
            "REJECTED: Discovery-only finding — you found a secret/token/key/endpoint but did not USE it. "
            "Discovery is reconnaissance, not a vulnerability. To fix: Show what you DID with the "
            "discovered item. Example: 'Found Firebase API key in JS bundle → called Firestore REST API "
            "→ read user documents from /users collection' is a valid finding. "
            "'Found Firebase API key in JS bundle' alone is NOT reportable. "
            "Add the HTTP requests you made with the discovered credential and the data you accessed."
        )
    if desc_text:
        _concrete_indicators = [
            "curl ",
            "POST ",
            "GET ",
            "PUT ",
            "DELETE ",
            "PATCH ",
            "request",
            "response",
            "HTTP/",
            "status code",
            "executed",
            "achieved",
            "obtained",
            "extracted",
            "accessed",
            "modified",
            "created",
            "deleted",
            "cookie",
            "token",
            "session",
            "payload",
            "before",
            "after",
            "step ",
            "first ",
            "then ",
        ]
        desc_lower = desc_text.lower()
        has_concrete = any(ind in desc_lower for ind in _concrete_indicators)
        has_theoretical = sum(1 for p in _THEORETICAL_PATTERNS if p in desc_lower)
        if not has_concrete and has_theoretical >= 2:
            errors.append(
                "REJECTED: Description is entirely theoretical (contains multiple hedging phrases like "
                "'could allow', 'may lead to', 'might be possible'). "
                "To fix: Rewrite the description with concrete evidence. Use past tense: "
                "'I sent POST /api/login with payload X → received 200 OK with admin session token → "
                "used token to access /api/admin/users'. Include actual HTTP requests/responses. "
                "Describe what you actually DID, not what could theoretically be done."
            )

    if not cvss_breakdown:
        errors.append(
            "REJECTED: cvss_breakdown must be a JSON object with all 8 CVSS v3.1 metrics. "
            'Example: {"attack_vector":"N","attack_complexity":"L","privileges_required":"N",'
            '"user_interaction":"N","scope":"U","confidentiality":"H","integrity":"H","availability":"H"}'
        )
        cvss_breakdown = {}
    else:
        for name, valid in _CVSS_VALID.items():
            value = cvss_breakdown.get(name)
            if value not in valid:
                errors.append(
                    f"REJECTED: Invalid CVSS metric '{name}': got '{value}'. Must be one of: {', '.join(valid)}"
                )

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    if errors:
        # Build a clear, actionable error message with the finding title
        title_display = title.strip() if title else "(no title)"
        error_lines = [
            f"REJECTED: Finding '{title_display}' was rejected for the following reason(s):"
        ]
        for i, err in enumerate(errors, 1):
            error_lines.append(f"  {i}. {err}")
        error_lines.append("")
        error_lines.append(
            "FIX THE ABOVE ISSUES AND RESUBMIT. Do not retry with the same content. "
            "Read each reason carefully — it tells you exactly what is missing or wrong."
        )
        return {
            "success": False,
            "error": "\n".join(error_lines),
            "title": title_display,
            "errors": errors,
        }

    # --- VALIDATION JUDGE: semantic evaluation of finding quality ---
    try:
        # POC VALIDATION: check if the PoC demonstrates real exploitation
        from prometheus.core.poc_validation import validate_finding_with_poc

        poc_validation = validate_finding_with_poc(
            {
                "title": title,
                "poc_description": poc_description,
                "poc_script_code": poc_script_code,
                "description": description,
                "impact": impact,
            },
            execute_poc=True,
            timeout=30,
        )  # Execute PoC: reports require working proof, not text-only claims

        if poc_validation["verdict"] != "exploitable" or not poc_validation.get("reportable"):
            return {
                "success": False,
                "error": (
                    f"REJECTED: Finding '{title}' did not produce a working exploitable PoC.\n"
                    f"  Verdict: {poc_validation['verdict']}\n"
                    f"  Reason: {poc_validation['reason']}\n"
                    f"  Missing: {poc_validation['missing']}\n"
                    f"  Evidence: {str(poc_validation.get('evidence', ''))[:500]}\n"
                    f"  Prometheus is a validator. Do not file until the PoC proves real security impact."
                ),
                "title": title,
                "poc_validation_verdict": poc_validation["verdict"],
                "poc_executed": poc_validation.get("poc_executed"),
                "poc_successful": poc_validation.get("poc_successful"),
            }

        from prometheus.core.validation_judge import validate_finding

        validation_verdict = validate_finding(
            {
                "title": title,
                "description": description,
                "impact": impact,
                "target": target,
                "technical_analysis": technical_analysis,
                "poc_description": poc_description,
                "poc_script_code": poc_script_code,
                "endpoint": endpoint or "",
                "cwe": cwe or "",
            }
        )
        if validation_verdict.verdict == "false_positive":
            return {
                "success": False,
                "error": (
                    f"REJECTED: Finding '{title}' classified as FALSE POSITIVE by validation judge.\n"
                    f"  Reason: {validation_verdict.reason}\n"
                    f"  Confidence: {validation_verdict.confidence}\n"
                    f"  This finding does not demonstrate a real security vulnerability. "
                    f"Do not resubmit without addressing the specific issues above."
                ),
                "title": title,
                "validation_verdict": validation_verdict.verdict,
            }
        if validation_verdict.verdict == "speculative":
            return {
                "success": False,
                "error": (
                    f"REJECTED: Finding '{title}' classified as SPECULATIVE by validation judge.\n"
                    f"  Reason: {validation_verdict.reason}\n"
                    f"  Missing: {validation_verdict.missing}\n"
                    f"  Confidence: {validation_verdict.confidence}\n"
                    f"  To make this a valid finding, you must demonstrate actual exploitation. "
                    f"Continue pursuing this vulnerability with the specific approach described above."
                ),
                "title": title,
                "validation_verdict": validation_verdict.verdict,
                "missing": validation_verdict.missing,
            }
        # validated — continue to accept
        logger.info(
            "Validation judge PASSED: %s (verdict=%s, confidence=%.2f)",
            title,
            validation_verdict.verdict,
            validation_verdict.confidence,
        )
    except Exception as exc:
        logger.warning("Validation judge failed (non-fatal, allowing finding): %s", exc)

    # --- LIVE VERIFICATION: confirm the vulnerability exists on the real target ---
    try:
        from prometheus.core.live_verification import verify_live

        live_result = verify_live(
            {
                "title": title,
                "target": target,
                "endpoint": endpoint or "",
                "description": description,
                "poc_description": poc_description,
            }
        )
        logger.info(
            "Live verification: verdict=%s verified=%s confidence=%.2f reason=%s",
            live_result.verdict,
            live_result.verified,
            live_result.confidence,
            live_result.reason[:100],
        )
        if live_result.verdict == "contradicted":
            return {
                "success": False,
                "error": (
                    f"REJECTED: Finding '{title}' CONTRADICTED by live verification.\n"
                    f"  Reason: {live_result.reason}\n"
                    f"  Evidence: {live_result.evidence[:300]}\n"
                    f"  Requests made: {live_result.requests_made}\n"
                    f"  The target does NOT behave as claimed. This finding is a false positive.\n"
                    f"  Do not resubmit without re-testing against the live target."
                ),
                "title": title,
                "live_verification": live_result.verdict,
                "live_evidence": live_result.evidence[:500],
            }
        if live_result.verdict == "confirmed":
            logger.info(
                "Live verification CONFIRMED: %s (confidence=%.2f, evidence=%s)",
                title,
                live_result.confidence,
                live_result.evidence[:200],
            )
        elif live_result.verdict in ("error", "unverifiable"):
            return {
                "success": False,
                "error": (
                    f"REJECTED: Finding '{title}' was not live-verified.\n"
                    f"  Verdict: {live_result.verdict}\n"
                    f"  Reason: {live_result.reason}\n"
                    f"  Evidence: {live_result.evidence[:300]}\n"
                    f"  Requests made: {live_result.requests_made}\n"
                    f"  Prometheus is a validator. Continue testing until the PoC is confirmed on the real target."
                ),
                "title": title,
                "live_verification": live_result.verdict,
                "live_evidence": live_result.evidence[:500],
            }
    except Exception as exc:
        return {
            "success": False,
            "error": (
                f"REJECTED: Live verification crashed for finding '{title}'.\n"
                f"  Error: {exc}\n"
                f"  Fix the PoC or verification path before reporting."
            ),
            "title": title,
            "live_verification": "error",
        }

    cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)

    # VRT classification for Bugcrowd targets
    vrt_category: str | None = None
    vrt_priority: int | None = None
    _is_bugcrowd = _detect_bugcrowd_target(target)
    if _is_bugcrowd:
        try:
            from prometheus.core.vrt_classifier import get_vrt_classifier

            vrt = get_vrt_classifier()
            vrt_result = vrt.classify(
                title=title,
                description=description or "",
                cwe=cwe or "",
                endpoint=endpoint or "",
            )
            vrt_category = vrt_result["vrt_category"]
            vrt_priority = vrt_result["priority"]
            logger.info(
                "Bugcrowd VRT classification: %s (P%s, %s, confidence=%.2f)",
                vrt_category,
                vrt_priority,
                vrt_result["priority_label"],
                vrt_result["confidence"],
            )
            # Warn if CVSS severity and VRT priority disagree significantly
            _vrt_to_severity = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "informational"}
            _expected_severity = _vrt_to_severity.get(vrt_priority, "medium")
            if severity != _expected_severity and vrt_result["confidence"] >= 0.7:
                logger.warning(
                    "CVSS severity (%s) disagrees with VRT priority P%s (%s) for '%s'. "  # codeql[py/clear-text-logging-sensitive-data] : severity/vrt/titles are public severity metadata, not secrets
                    "Consider adjusting CVSS to match VRT classification.",
                    severity,  # codeql[py/clear-text-logging-sensitive-data] : suppressed via the security dashboard triage
                    vrt_priority,
                    _expected_severity,
                    title,
                )
        except Exception:
            logger.debug("VRT classification failed (non-blocking)", exc_info=True)

    try:
        from prometheus.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; vulnerability report not persisted")
            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created (not persisted)",
                "warning": "Report could not be persisted - report state unavailable",
            }

        # LAYER 1: Knowledge store dedup (fast, deterministic)
        # Check against existing findings in the knowledge store
        # This catches duplicates across scans before hitting the LLM dedup.
        # Five layers run inside find_duplicate_finding: exact hash,
        # CWE+endpoint, normalized title, BM25, and external_submissions.
        existing_vuln_id: int | None = None
        dedup_layer: str | None = None
        dedup_match: dict[str, Any] | None = None
        domain: str = ""
        try:
            from prometheus.tools.knowledge.store import KnowledgeStore

            ks = KnowledgeStore()
            domain = target or ""
            if domain:
                from urllib.parse import urlparse

                parsed = urlparse(domain if "://" in domain else f"https://{domain}")
                domain = parsed.netloc or parsed.path.split("/")[0]

                dup_check = ks.find_duplicate_finding(
                    domain=domain,
                    finding_title=title,
                    endpoint=endpoint or "",
                    cwe=cwe or "",
                )
                if dup_check:
                    dedup_layer = dup_check.get("layer")
                    dedup_match = dup_check
                    # exact_hash / cwe_endpoint / title_similarity / bm25 all
                    # populate 'finding'; external / external_bm25 populate
                    # 'external' and have finding=None.
                    if dup_check.get("finding"):
                        existing_vuln_id = dup_check["finding"].get("id")
        except Exception as exc:
            logger.debug("Knowledge store dedup check failed (non-blocking): %s", exc)

        # If the dedup hit was against an external (Bugcrowd/H1) closure
        # rather than a local report_status row, consult should_revalidate
        # to decide whether to block the report, file it, or update the
        # external record's notes. This is the path that prevents
        # re-submitting a finding the user already filed and was rejected.
        external_only_dedup = (
            dedup_match
            and dedup_match.get("finding") is None
            and dedup_match.get("external") is not None
        )
        if external_only_dedup and existing_vuln_id is None and dedup_match is not None:
            try:
                from prometheus.tools.knowledge.store import KnowledgeStore

                ks = KnowledgeStore()
                policy = ks.should_revalidate(
                    domain=domain,
                    finding_title=title,
                    endpoint=endpoint or "",
                    cwe=cwe or "",
                )
                if policy.get("action") == "archive":
                    logger.info(
                        "DEDUP BLOCK: '%s' matches external closure (%s) — %s",
                        title,
                        dedup_layer,
                        policy.get("reason"),
                    )
                    return {
                        "success": False,
                        "error": (
                            f"DEDUP BLOCKED: this finding matches a previously "
                            f"closed external submission "
                            f"({dedup_match['external'].get('platform')}/"
                            f"{dedup_match['external'].get('external_id')}, "
                            f"status='{dedup_match['external'].get('status')}'). "
                            f"Reason: {policy.get('reason')}. "
                            f"See external_submissions row for triager notes. "
                            f"Do not re-file without a material new chain of evidence."
                        ),
                        "title": title,
                        "dedup_layer": dedup_layer,
                        "external_submission": dedup_match.get("external"),
                    }
                if policy.get("action") == "revalidate":
                    # Run a cheap live probe to see if the surface has
                    # actually changed before allowing the new report.
                    try:
                        from prometheus.core.auto_revalidate import live_revalidate

                        probe = live_revalidate(
                            {
                                "finding_title": title,
                                "domain": domain,
                                "endpoint": endpoint or "",
                                "vuln_type": (cwe or "").lower(),
                            }
                        )
                        logger.info(
                            "should_revalidate=revalidate; live probe: changed=%s evidence=%s",
                            probe.get("changed"),
                            (probe.get("evidence") or "")[:200],
                        )
                        if probe.get("changed") is False:
                            return {
                                "success": False,
                                "error": (
                                    f"DEDUP BLOCKED (live revalidation): surface behavior "
                                    f"has not changed since the prior closure. "
                                    f"Probe: {probe.get('probe')}; "
                                    f"Evidence: {probe.get('evidence')[:400]}"
                                ),
                                "title": title,
                                "dedup_layer": dedup_layer,
                                "external_submission": dedup_match.get("external"),
                                "live_probe": probe,
                            }
                    except Exception as e:  # noqa: BLE001
                        logger.debug("Live revalidate crashed (non-blocking): %s", e)
            except Exception as e:  # noqa: BLE001
                logger.debug("should_revalidate check failed (non-blocking): %s", e)

        # LAYER 2: LLM-based semantic dedup (slower, handles fuzzy matches)
        from prometheus.report.dedupe import check_duplicate

        existing = report_state.get_existing_vulnerabilities()
        candidate = {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "endpoint": endpoint,
            "method": method,
        }
        dedupe = await check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            existing_vuln_id = dedupe.get("duplicate_id")
            if not existing_vuln_id:
                existing_vuln_id = next(
                    (r.get("id") for r in existing if r.get("id") == dedupe.get("duplicate_id")),
                    None,
                )

        # --- TIMELINE UPDATE instead of reject ---
        # When a rescan finds the same vuln, update the existing report with
        # a new timeline entry rather than creating a duplicate or rejecting.
        if existing_vuln_id is not None:
            try:
                from prometheus.core.scan_persistence import ScanPersistence
                from datetime import UTC, datetime

                sp = ScanPersistence()
                now_ts = datetime.now(UTC).isoformat()

                # Add a timeline comment with new scan evidence
                timeline_entry = (
                    f"=== Rescan verification [{now_ts[:19]}] ===\n"
                    f"Re-verified by scan: {getattr(report_state, 'run_name', 'unknown')}\n"
                    f"Status: revalidated (still present)\n"
                    f"Technique: {method or 'N/A'}\n"
                    f"Endpoint: {endpoint or target}\n"
                    f"New PoC evidence added with updated details."
                )
                # Insert into finding_comments
                db_path = getattr(sp, "_db_path", None)
                if db_path:
                    import sqlite3 as _sqlite3

                    _conn = _sqlite3.connect(str(db_path))
                    _conn.execute(
                        "INSERT INTO finding_comments (finding_id, comment_type, content, version, created_at) "
                        "VALUES (?, ?, ?, "
                        "(SELECT COALESCE(MAX(version), 0) + 1 FROM finding_comments WHERE finding_id = ?), ?)",
                        (
                            existing_vuln_id,
                            "verification",
                            timeline_entry,
                            existing_vuln_id,
                            now_ts,
                        ),
                    )
                    # Update report status
                    _conn.execute(
                        "UPDATE report_status SET status = 'revalidated', last_verified_at = ?, "
                        "updated_at = ?, notes = COALESCE(notes || '\n---\n', '') || ? "
                        "WHERE id = ?",
                        (
                            now_ts,
                            now_ts,
                            f"[{now_ts[:19]}] Revalidated by scan {getattr(report_state, 'run_name', 'unknown')}: {title}",
                            existing_vuln_id,
                        ),
                    )
                    _conn.commit()
                    _conn.close()
                    logger.info(
                        "Timeline updated for existing finding %d: revalidated by scan %s",
                        existing_vuln_id,
                        getattr(report_state, "run_name", "unknown"),
                    )
                return {
                    "success": True,
                    "message": (
                        f"REVALIDATED — '{title}' (id={existing_vuln_id}) was already tracked. "
                        f"Added new timeline entry with this scan's verification data. "
                        f"Status updated to revalidated."
                    ),
                    "existing_id": existing_vuln_id,
                    "action": "revalidated",
                }
            except Exception as timeline_err:
                logger.exception(
                    "Failed to update timeline for existing finding %d", existing_vuln_id
                )
                return {
                    "success": False,
                    "error": (
                        f"DUPLICATE DETECTED: finding id={existing_vuln_id} already exists, "
                        f"but timeline update failed: {timeline_err}. "
                        f"Does your new finding target a DIFFERENT endpoint?"
                    ),
                    "duplicate_of": existing_vuln_id,
                }

        report_id = report_state.add_vulnerability_report(
            title=title,
            description=description,
            severity=severity,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            cvss=cvss_score,
            cvss_breakdown=cvss_breakdown,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=parsed_locations,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )

        # Immediately sync to report_status so the Reports tab shows it in real time
        try:
            import json as _json

            from prometheus.tools.knowledge.store import KnowledgeStore as _KS

            _ks = _KS()
            _domain = target or ""
            if _domain:
                from urllib.parse import urlparse as _urlparse

                _parsed = _urlparse(_domain if "://" in _domain else f"https://{_domain}")
                _domain = _parsed.netloc or _parsed.path.split("/")[0]

            _finding_snapshot = {
                "id": report_id,
                "title": title,
                "description": description,
                "severity": severity,
                "impact": impact,
                "target": target,
                "technical_analysis": technical_analysis,
                "poc_description": poc_description,
                "poc_script_code": poc_script_code,
                "remediation_steps": remediation_steps,
                "cvss": cvss_score,
                "cvss_breakdown": cvss_breakdown,
                "endpoint": endpoint,
                "method": method,
                "cve": cve,
                "cwe": cwe,
                "code_locations": parsed_locations,
            }
            if vrt_category:
                _finding_snapshot["vrt_category"] = vrt_category
                _finding_snapshot["vrt_priority"] = vrt_priority
            _snapshot_json = _json.dumps(_finding_snapshot, default=str, ensure_ascii=False)
            _ks.upsert_report_status(
                domain=_domain,
                scan_id=report_state.run_id,
                finding_title=title,
                status="new",
                severity=severity,
                cvss=cvss_score,
                endpoint=endpoint,
                cwe=cwe,
                full_finding_json=_snapshot_json,
            )
            try:
                from prometheus.core.candidate_store import CandidateStore as _CandidateStore

                _candidate_snapshot = dict(_finding_snapshot)
                _candidate_snapshot["fingerprint"] = _ks._finding_hash(title, endpoint or "")
                _CandidateStore().ingest_raw_finding(
                    _candidate_snapshot,
                    domain=_domain,
                    scan_id=report_state.run_id,
                    source_tool="reporting_tool",
                    source_type="agent_report",
                )
            except Exception:
                logger.warning(
                    "Canonical candidate sync failed for '%s' (non-critical)", title, exc_info=True
                )
            logger.info(
                "Synced finding '%s' to report_status and finding_candidates in real time", title
            )
        except Exception as exc:
            logger.debug("Real-time report_status sync failed (non-blocking): %s", exc)
    except (ImportError, AttributeError) as e:
        logger.exception("create_vulnerability_report persistence failed")
        return {
            "success": False,
            "error": f"INTERNAL ERROR: Failed to persist vulnerability report '{title}': {e!s}. This is a system issue, not a validation problem — try again.",
        }
    else:
        logger.info(
            "Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",  # codeql[py/clear-text-logging-sensitive-data] : report metadata (id, severity, cvss, title) is not sensitive
            report_id,
            severity,  # codeql[py/clear-text-logging-sensitive-data] : suppressed via the security dashboard triage
            cvss_score,  # codeql[py/clear-text-logging-sensitive-data] : suppressed via the security dashboard triage
            title,
        )
        result = {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cvss_score": cvss_score,
        }
        if vrt_category and vrt_priority is not None:
            result["vrt_category"] = vrt_category
            result["vrt_priority"] = vrt_priority
        return result


@function_tool(timeout=180, strict_mode=False)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    hypothesis_id: str | None = None,
    positive_controls: list[dict[str, Any]] | None = None,
    negative_controls: list[dict[str, Any]] | None = None,
    validation_agent_id: str | None = None,
    scan_id: str | None = None,
) -> str:
    """File a vulnerability report — one report per fully-verified finding.

    **When to file**: you have a concrete vulnerability or security
    misconfiguration with PROVEN security impact. The finding must meet
    ALL three criteria:
    1. The vulnerability exists (technical proof with evidence)
    2. It has security impact (data access, code execution, account compromise)
    3. An attacker could exploit it (not just theoretical)

    **HackerOne Platform Standards** — reports that violate these are REJECTED:

    - Missing security headers WITHOUT demonstrated impact are
      INFORMATIONAL — do NOT file as Medium/Low. Only file if you can
      demonstrate the concrete attack that the missing header enables.
      A ``curl -I`` output showing a missing header is NOT sufficient
      proof — you must show the attack the missing header permits.
    - Clickjacking on non-sensitive actions is Informational.
    - Version disclosure/banner grabbing without exploitable
      vulnerability is Informational.
    - Deprecated TLS/SSL ciphers without exploitable vulnerability is
      Informational.
    - Self-XSS is NOT reportable.
    - IDOR with unpredictable/randomized IDs IS valid — use AC:H in
      CVSS to reflect the unpredictability.
    - PII disclosure (phone numbers, passport numbers, addresses, SSNs)
      should be scored as Critical severity.
    - Cross-tenant data access is always at least High severity.
    - Automated findings MUST be contextualized — explain WHY the
      finding matters in the specific business context of the target.

    **What IS reportable** (high-value findings that get paid):

    - Authentication/Authorization bypass — accessing other users' data or admin functions
    - Remote Code Execution — executing arbitrary commands on the server
    - SQL Injection with data access — extracting database contents, not just error messages
    - SSRF with internal network access — reaching cloud metadata APIs or internal services
    - Account Takeover — resetting/hijacking another user's account via logic flaws
    - Sensitive data exposure — PII, API keys, tokens, passwords accessible without authorization
    - XSS with session theft — XSS that steals cookies/tokens, not just defacement
    - CSRF on critical actions — changing email/password/payment without user consent
    - Privilege escalation — regular user accessing admin functions
    - API key/token leakage — hardcoded secrets in source code that grant access

    **What is NOT reportable** (these get rejected — do NOT file):

    - Missing security headers (CSP, X-Frame-Options) without demonstrated exploit chain
    - Version disclosure (server headers, error pages) with no security impact
    - CORS on public APIs (usually intentional — only report if you PROVE response body is readable cross-origin)
    - Rate limiting issues on non-sensitive endpoints
    - Cookie flags missing on non-session cookies
    - HTTP Host header injection without demonstrated impact
    - Self-XSS (requires user to paste code in their own console)
    - Open redirect via javascript: or data: URIs
    - Denial of Service findings
    - Vulnerabilities in third-party services not under program control
    - Model behavior issues (jailbreaks, hallucinations, bias)

    **Report quality requirements**:

    - Impact framing: write from attacker's perspective ("An attacker can take over
      any account by knowing only their email" — NOT "CSRF in email change endpoint")
    - Exact reproduction: numbered steps with exact URLs, HTTP request/response dumps
    - Working PoC: actual exploit code or request sequences, not theoretical descriptions
    - CVSS scoring: include CVSS v3.1 vector string for every finding
    - Concise: 500-1500 words per report, no fluff
    - HTTP evidence: include the exact HTTP request AND response that demonstrates
      the vulnerability
    - Business impact: explain the business impact from an attacker's perspective
    - Technology-specific remediation: include suggested remediation specific to the
      technology stack being used

    **When NOT to file**:

    - General security observations without a specific vulnerability.
    - Suspicions you haven't confirmed with evidence.
    - Tracking multiple vulnerabilities at once — one report per vuln.
    - Re-reporting something you (or another agent) already filed.
    - Findings that consist solely of discovering credentials, keys, tokens,
      configuration values, or internal architecture details without demonstrating
      unauthorized access using those discoveries. "I found an API key" is
      reconnaissance. "I used the API key to read user data" is a vulnerability.
      If the PoC ends at extraction without demonstrating use, do not file.
    - Third-party analytics cookies (GA _ga/_gid with SameSite=None;Secure
      are expected — do NOT flag).

    Automatic LLM-based **deduplication** rejects reports that describe
    the same root cause on the same asset as an existing report. If you
    get a ``duplicate_of`` response, do NOT retry — move on to other
    areas.

    **Customer-facing report rules** (the report is PDF-rendered for
    delivery):

    - No internal/system details: never mention paths like
      ``/workspace``, internal tools, agents, sandboxes, models, system
      prompts, internal errors / stack traces, or tester environment.
    - Tone: formal, objective, third-person, vendor-neutral, concise.
    - Standard finding structure: Overview → Severity & CVSS →
      Affected assets → Technical details → PoC (steps + code) →
      Impact → Remediation → Evidence (in technical_analysis).
    - Numbered steps allowed only in PoC and Remediation sections.
    - Avoid hedging language; be precise and non-vague.

    **White-box requirement**: when source is available, you MUST
    populate ``code_locations``. See the ``code_locations`` arg below
    for the full rules around ``fix_before`` / ``fix_after``,
    multi-part fixes, and informational-vs-actionable entries.

    **CVSS breakdown** is an object with all 8 metrics (each a single
    uppercase letter):

    - ``attack_vector``: ``N`` (Network), ``A`` (Adjacent), ``L``
      (Local), ``P`` (Physical)
    - ``attack_complexity``: ``L`` / ``H``
    - ``privileges_required``: ``N`` / ``L`` / ``H``
    - ``user_interaction``: ``N`` / ``R``
    - ``scope``: ``U`` (Unchanged) / ``C`` (Changed)
    - ``confidentiality`` / ``integrity`` / ``availability``: ``N`` /
      ``L`` / ``H``

    Example::

        {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H"
        }

    **CVE / CWE rules**: pass the bare ID only (``CVE-2024-1234``,
    ``CWE-89``) — no name, no parenthetical. Be 100% certain; if
    unsure, use ``web_search`` to verify the ID before passing, or omit
    the field entirely. Always prefer the most specific child CWE over
    a broad parent (CWE-89 not CWE-74; CWE-78 not CWE-77). Do NOT use
    broad/parent CWEs like CWE-74, CWE-20, CWE-200, CWE-284, or
    CWE-693.

    Common CWE references (use the ID only — names are listed here
    just for your lookup):

    - **Injection**: CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command
      Injection, CWE-94 Code Injection, CWE-77 Command Injection.
    - **Auth / Access**: CWE-287 Improper Authentication, CWE-862
      Missing Authorization, CWE-863 Incorrect Authorization, CWE-306
      Missing Auth for Critical Function, CWE-639 Authz Bypass via
      User-Controlled Key.
    - **Web**: CWE-352 CSRF, CWE-918 SSRF, CWE-601 Open Redirect,
      CWE-434 Unrestricted File Upload.
    - **Memory**: CWE-787 OOB Write, CWE-125 OOB Read, CWE-416 UAF,
      CWE-120 Classic Buffer Overflow.
    - **Data**: CWE-502 Deserialization of Untrusted Data, CWE-22
      Path Traversal, CWE-611 XXE.
    - **Crypto / Config**: CWE-798 Hard-coded Credentials, CWE-327
      Broken / Risky Crypto, CWE-311 Missing Encryption, CWE-916 Weak
      Password Hashing.

    Args:
        title: Specific finding title (e.g.
            ``"SQL Injection in /api/users login parameter"``). Don't
            include the CVE number in the title.
        description: How the vuln was discovered + what it is.
        impact: What an attacker achieves; business risk; data at risk.
        target: Affected URL / domain / repository.
        technical_analysis: The mechanism and root cause.
        poc_description: Step-by-step reproduction.
        poc_script_code: Working PoC (Python preferred).
        remediation_steps: Specific, actionable fix.
        cvss_breakdown: 8-metric object per the format above.
        endpoint: API path / Git path (e.g. ``/api/login``).
        method: HTTP method when relevant.
        cve: ``CVE-YYYY-NNNNN`` if certain, else omit.
        cwe: ``CWE-NNN`` (most specific child) if certain, else omit.
        code_locations: White-box findings — list of location objects.
        hypothesis_id: Preferred validation handle from create_hypothesis.
            If provided, it must reference a validated hypothesis with at
            least two passed positive controls and one passed negative control.
        positive_controls: Explicit positive validation evidence when a
            hypothesis_id is not available. At least two passed controls are
            required.
        negative_controls: Explicit negative validation evidence when a
            hypothesis_id is not available. At least one passed control is
            required.
        validation_agent_id: Independent validation agent that verified the
            finding when explicit controls are supplied.

            **How ``fix_before`` / ``fix_after`` work**: they're used as
            literal GitHub/GitLab PR suggestion blocks. When a reviewer
            accepts the suggestion, the platform replaces the **exact
            lines from ``start_line`` to ``end_line``** with
            ``fix_after``. Therefore:

            1. ``fix_before`` must be a **VERBATIM** copy of the source
               at those lines — same whitespace, indentation, line
               breaks. If it doesn't match character-for-character, the
               suggestion will corrupt the code when accepted.
            2. ``fix_after`` is the COMPLETE replacement for that
               entire block (may be more or fewer lines).
            3. ``start_line`` / ``end_line`` must precisely cover the
               lines in ``fix_before`` — no more, no less.

            **Multi-part fixes**: many fixes touch multiple
            non-contiguous parts of a file (e.g. add an import at the
            top AND change code lower down). Since each
            ``fix_before`` / ``fix_after`` pair covers ONE contiguous
            block, create **separate location entries** for each
            non-contiguous part. Use ``label`` to describe each part's
            role (``"Add escape helper import"``, ``"Sanitize input
            before SQL"``). Order primary fix first, supporting
            changes (imports, config) after.

            **Informational vs actionable**:
            - With ``fix_before`` / ``fix_after``: actionable fix
              (renders as a PR suggestion block).
            - Without them: informational context (e.g. showing the
              source of tainted data, or a sink that doesn't need
              direct editing).

            **Per-location fields**:
            - ``file`` (REQUIRED): path **relative** to repo root. No
              leading slash, no ``..``, no ``/workspace/`` prefix.
              Right: ``"src/db/queries.ts"``. Wrong:
              ``"/workspace/repo/src/db/queries.ts"``, ``"./src/x.py"``,
              ``"../../etc/passwd"``.
            - ``start_line`` (REQUIRED): 1-based; positive integer.
              Verify against the actual file — do NOT guess.
            - ``end_line`` (REQUIRED): 1-based; ``>= start_line``.
              Only equal to ``start_line`` when the block truly is one
              line.
            - ``snippet`` (optional): verbatim source at this range.
            - ``label`` (optional): short role description; especially
              important for multi-part fixes.
            - ``fix_before`` (optional): verbatim copy of the
              vulnerable code, lines ``start_line``-``end_line``.
            - ``fix_after`` (optional): complete replacement for that
              block; syntactically valid.

            **Common mistakes to avoid**:
            - Guessing line numbers instead of reading the file.
            - Paraphrasing / reformatting code in ``fix_before``.
            - Setting ``start_line == end_line`` when the vulnerable
              code spans multiple lines.
            - Bundling an import addition and a far-away code change
              into one location — split them.
            - Padding ``fix_before`` with surrounding context lines
              that aren't part of the fix.
            - Duplicating the same change across multiple locations.
    """
    logger.debug(
        "create_vulnerability_report: title=%s target=%s endpoint=%s", title[:60], target, endpoint
    )
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None

    # The function_tool signature accepts ``scan_id`` as an explicit arg so
    # SDK consumers can pass it directly, but a child invocation from a
    # tool-wrapping Agent will see the value through ctx.context — prefer
    # the context value when present so the retry guard scopes to the
    # actual running scan, not a stale caller-provided id.
    ctx_scan_id = inner.get("scan_id") if isinstance(inner, dict) else None
    if isinstance(ctx_scan_id, str) and ctx_scan_id.strip():
        scan_id = ctx_scan_id

    result = await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
        hypothesis_id=hypothesis_id,
        positive_controls=positive_controls,
        negative_controls=negative_controls,
        validation_agent_id=validation_agent_id,
        agent_id=agent_id,
        agent_name=agent_name,
        scan_id=scan_id,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
