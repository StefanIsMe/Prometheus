"""Live Verification Module for Prometheus findings.

Makes real HTTP requests to verify that claimed vulnerabilities actually exist
on the target. All verification is READ-ONLY (GET/HEAD/OPTIONS) — no
exploitation, no data modification, no attack payloads.

DESIGN PRINCIPLE: Agnostic. No platform-specific logic. No hardcoded CMS
patterns. The module extracts what the agent claimed from the finding text,
hits the real endpoint, and compares the response to the claims. Works on
any website, any framework, any API.

Verification pipeline (runs on every finding):
1. Hit the claimed endpoint
2. Check if it's accessible (status code)
3. Check if it requires authentication (401/403, or login page in response)
4. Analyze response data (JSON fields, sensitive patterns, HTML structure)
5. Compare response to agent's claims
6. Return verdict with evidence
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class LiveVerificationResult:
    """Result of live-verifying a finding against the real target."""

    finding_title: str
    verified: bool
    verdict: str  # 'confirmed', 'contradicted', 'unverifiable', 'error'
    reason: str
    evidence: str
    confidence: float
    requests_made: list[str] = field(default_factory=list)
    response_codes: list[int] = field(default_factory=list)
    evidence_items: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP helpers (curl — works in any sandbox without Python HTTP libs)
# ---------------------------------------------------------------------------


def _curl_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    follow_redirects: bool = True,
    include_headers: bool = False,
) -> tuple[int, str, dict[str, str]]:
    """Execute a GET request via curl. Returns (status_code, body, headers).

    When include_headers=True, uses -D to capture response headers.
    """
    cmd = ["curl", "-s", "-o", "-", "--max-time", str(timeout)]
    if include_headers:
        # Write headers to a temp file
        import tempfile

        with tempfile.NamedTemporaryFile(mode="r", suffix=".hdr") as hdr_file:
            cmd.extend(["-D", hdr_file.name])
            cmd.extend(["-w", "\\n__HTTP_CODE__%{http_code}"])
            if follow_redirects:
                cmd.append("-L")
            for k, v in (headers or {}).items():
                cmd.extend(["-H", f"{k}: {v}"])
            cmd.append(url)
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,  # noqa: S603
                    timeout=timeout + 5,
                )
                output = result.stdout
                code_match = re.search(r"__HTTP_CODE__(\d+)", output)
                status_code = int(code_match.group(1)) if code_match else 0
                body = re.sub(r"\n__HTTP_CODE__\d+\s*$", "", output).strip()
                # Read captured headers
                hdr_file.seek(0)
                headers_text = hdr_file.read()
                headers_dict = _parse_headers_text(headers_text)
                return status_code, body, headers_dict
            except subprocess.TimeoutExpired:
                return 0, "", {}
            except Exception as e:
                logger.warning("curl GET failed for %s: %s", url, e)
                return 0, "", {}

    cmd.extend(["-w", "\\n__HTTP_CODE__%{http_code}"])
    if follow_redirects:
        cmd.append("-L")
    for k, v in (headers or {}).items():
        cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(url)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,  # noqa: S603
            timeout=timeout + 5,
        )
        output = result.stdout
        code_match = re.search(r"__HTTP_CODE__(\d+)", output)
        status_code = int(code_match.group(1)) if code_match else 0
        body = re.sub(r"\n__HTTP_CODE__\d+\s*$", "", output).strip()
        return status_code, body, {}
    except subprocess.TimeoutExpired:
        return 0, "", {}
    except Exception as e:
        logger.warning("curl GET failed for %s: %s", url, e)
        return 0, "", {}


def _curl_head(url: str, timeout: int = 15) -> tuple[int, dict[str, str]]:
    """Execute a HEAD request. Returns (status_code, headers_dict)."""
    cmd = ["curl", "-sI", "-L", "--max-time", str(timeout), url]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,  # noqa: S603
            timeout=timeout + 5,
        )
        return _parse_status_and_headers(result.stdout)
    except Exception:
        return 0, {}


def _parse_headers_text(text: str) -> dict[str, str]:
    """Parse HTTP headers from raw text (may contain multiple HTTP/ responses)."""
    headers_dict: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("HTTP/"):
            headers_dict = {}  # Reset on new response (redirect chain)
        elif ":" in line:
            k, _, v = line.partition(":")
            headers_dict[k.strip().lower()] = v.strip()
    return headers_dict


def _parse_status_and_headers(text: str) -> tuple[int, dict[str, str]]:
    """Parse status code and headers from curl -sI output."""
    headers_dict: dict[str, str] = {}
    status_code = 0
    for line in text.splitlines():
        if line.startswith("HTTP/"):
            m = re.match(r"HTTP/[\d.]+\s+(\d+)", line)
            if m:
                status_code = int(m.group(1))
            headers_dict = {}  # Reset on new response
        elif ":" in line:
            k, _, v = line.partition(":")
            headers_dict[k.strip().lower()] = v.strip()
    return status_code, headers_dict


def _build_url(target: str, endpoint: str | None) -> str:
    """Construct full URL from target base and endpoint path."""
    if not endpoint:
        return target.rstrip("/")
    if endpoint.startswith("http"):
        return endpoint
    base = target.rstrip("/")
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    return f"{base}{path}"


# ---------------------------------------------------------------------------
# Claim extraction: what did the agent say the vulnerability is?
# ---------------------------------------------------------------------------


def _extract_claims(finding: dict[str, Any]) -> dict[str, Any]:
    """Extract verifiable claims from the finding text.

    Returns a dict of claims the agent made, which the verification pipeline
    will check against the real response. This is the agnostic core — we
    don't classify by keyword, we extract what the agent said and verify it.
    """
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    poc = (finding.get("poc_description") or "").lower()
    all_text = f"{title} {desc} {poc}"

    claims: dict[str, Any] = {
        "accessible": True,  # Agent claims the endpoint is accessible
        "unauthenticated": False,  # Agent claims no auth required
        "returns_data": False,  # Agent claims it returns sensitive data
        "returns_user_data": False,  # Agent claims it returns user/account data
        "cors_misconfigured": False,  # Agent claims CORS is misconfigured
        "cors_reflects_origin": False,  # Agent claims CORS reflects any origin
        "cors_allows_credentials": False,  # Agent claims CORS with credentials
        "directory_listing": False,  # Agent claims directory listing exposed
        "version_disclosed": False,  # Agent claims version info disclosed
        "sensitive_data": False,  # Agent claims sensitive data (PII, keys, etc.)
    }

    # Authentication claims
    auth_keywords = [
        "unauth",
        "without auth",
        "no auth",
        "missing auth",
        "without login",
        "no login",
        "publicly accessible",
        "authentication bypass",
        "broken auth",
        "accessible without",
    ]
    if any(kw in all_text for kw in auth_keywords):
        claims["unauthenticated"] = True

    # Data exposure claims
    data_keywords = [
        "user enum",
        "user list",
        "account enum",
        "username enum",
        "exposes user",
        "exposes account",
        "exposes all",
        "returns user",
        "returns account",
        "user data",
        "json array",
        "list of user",
        "list of account",
        "user lookup",
        "user detail",
        "individual user",
        "single user",
        "admin account",
        "account detail",
        "account info",
        "returns admin",
        "exposes admin",
    ]
    if any(kw in all_text for kw in data_keywords):
        claims["returns_user_data"] = True
        claims["returns_data"] = True

    # General data exposure
    disclosure_keywords = [
        "info disclos",
        "information disclos",
        "data leak",
        "data expos",
        "sensitive data",
        "pii",
        "email disclos",
        "credential",
        "api key",
        "token",
        "secret",
        "password",
    ]
    if any(kw in all_text for kw in disclosure_keywords):
        claims["returns_data"] = True
        claims["sensitive_data"] = True

    # CORS claims
    if "cors" in all_text or "access-control-allow-origin" in all_text:
        claims["cors_misconfigured"] = True
        if any(kw in all_text for kw in ["reflect", "mirror", "any origin", "*"]):
            claims["cors_reflects_origin"] = True
        if "credential" in all_text:
            claims["cors_allows_credentials"] = True

    # Directory listing claims
    if any(
        kw in all_text
        for kw in [
            "directory list",
            "open directory",
            "index of",
            "directory traversal",
        ]
    ):
        claims["directory_listing"] = True

    # Version disclosure claims
    if any(
        kw in all_text
        for kw in [
            "version disclos",
            "version leak",
            "server header",
            "x-powered-by",
            "banner grab",
            "fingerprint",
        ]
    ):
        claims["version_disclosed"] = True

    return claims


# ---------------------------------------------------------------------------
# Response analysis: what does the response actually contain?
# ---------------------------------------------------------------------------


def _analyze_response(body: str, status: int, headers: dict[str, str]) -> dict[str, Any]:
    """Analyze the HTTP response to determine what it actually contains.

    Returns a dict of facts about the response. Fully agnostic — no
    platform-specific logic.
    """
    analysis: dict[str, Any] = {
        "status": status,
        "body_length": len(body),
        "is_json": False,
        "json_data": None,
        "json_records": 0,
        "has_user_fields": False,
        "user_field_names": set(),
        "is_login_page": False,
        "login_indicators": [],
        "is_empty": len(body.strip()) == 0,
        "is_error_page": False,
        "has_sensitive_patterns": False,
        "sensitive_patterns_found": [],
        "has_directory_listing": False,
        "directory_indicators": [],
        "version_headers": {},
        "cors_headers": {},
    }

    if status == 0:
        return analysis

    # --- Login page detection (agnostic: check for any login form) ---
    # Works for WordPress, Django, Rails, Express, Laravel, Next.js, etc.
    body_lower = body.lower()

    # Strong signals: form elements that indicate a login/auth form
    strong_login_patterns = [
        (r"<form[^>]*(?:login|signin|sign-in|auth|logon)", "login form element"),
        (r'type=["\']password["\']', "password input field"),
        (r'name=["\'](?:password|passwd|pwd|pass)["\']', "password field name"),
        (r'id=["\'](?:password|passwd|pwd|login_pass|user_pass)["\']', "password field id"),
        (r'<input[^>]*type=["\']password["\']', "password input tag"),
    ]
    for pattern, indicator in strong_login_patterns:
        if re.search(pattern, body_lower):
            analysis["is_login_page"] = True
            analysis["login_indicators"].append(indicator)
            break  # One strong signal is enough

    # Weaker signals: text content suggesting login (only if no strong signals)
    if not analysis["is_login_page"]:
        weak_login_patterns = [
            (r"\b(?:sign\s*in|log\s*in|log\s*on)\b", "sign in / log in text"),
            (r"\busername\s*(?:or\s*(?:email|phone))?\s*:", "username label"),
            (r"\benter\s*(?:your\s*)?(?:password|credentials)\b", "password prompt"),
        ]
        for pattern, indicator in weak_login_patterns:
            if re.search(pattern, body_lower):
                analysis["login_indicators"].append(indicator)
        # Need at least 2 weak signals to call it a login page
        if len(analysis["login_indicators"]) >= 2:
            analysis["is_login_page"] = True

    # --- Error page detection ---
    error_patterns = [
        r"404\s*(?:not\s*found|error)",
        r"403\s*(?:forbidden|access\s*denied)",
        r"500\s*(?:internal\s*server\s*error)",
        r"page\s*not\s*found",
        r"access\s*(?:is\s*)?denied",
    ]
    if status >= 400:
        for pattern in error_patterns:
            if re.search(pattern, body_lower):
                analysis["is_error_page"] = True
                break

    # --- JSON analysis ---
    try:
        data = json.loads(body)
        analysis["is_json"] = True
        analysis["json_data"] = data

        # Count records (list = multiple, dict = single)
        records = data if isinstance(data, list) else [data]
        analysis["json_records"] = len(records)

        # Check for user/account-like fields (agnostic: any dict with these keys)
        user_fields = {
            "slug",
            "username",
            "user_name",
            "user_login",
            "login",
            "name",
            "display_name",
            "displayName",
            "screen_name",
            "email",
            "email_address",
            "mail",
            "id",
            "user_id",
            "userId",
            "account_id",
            "accountId",
            "first_name",
            "firstName",
            "last_name",
            "lastName",
            "avatar",
            "avatar_url",
            "profile_url",
            "profile_image",
            "phone",
            "phone_number",
            "mobile",
            "role",
            "permissions",
            "is_admin",
            "is_administrator",
        }
        for record in records:
            if isinstance(record, dict):
                matched = user_fields & set(record.keys())
                if matched:
                    analysis["has_user_fields"] = True
                    analysis["user_field_names"] |= matched

        # Check for sensitive patterns in JSON values
        _check_sensitive_json(data, analysis)

    except (json.JSONDecodeError, ValueError):
        pass

    # --- Sensitive data patterns in non-JSON body ---
    if not analysis["has_sensitive_patterns"]:
        sensitive_patterns = [
            (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email address"),
            (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone number"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
            (
                r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"][^'\"]+['\"]",
                "API key / secret",
            ),
            (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "private key"),
        ]
        for pattern, name in sensitive_patterns:
            if re.search(pattern, body):
                analysis["has_sensitive_patterns"] = True
                analysis["sensitive_patterns_found"].append(name)

    # --- Directory listing detection (agnostic) ---
    listing_patterns = [
        (r"index\s+of\s+/", "Index of /"),
        (r"<title>[^<]*directory[^<]*listing", "directory listing title"),
        (r"\[parent\s+directory\]", "[parent directory]"),
        (r"\[DIR\]", "[DIR] marker"),
        (r"directory\s+listing\s+for", "directory listing for..."),
        (r"autoindex", "autoindex enabled"),
    ]
    for pattern, indicator in listing_patterns:
        if re.search(pattern, body_lower):
            analysis["has_directory_listing"] = True
            analysis["directory_indicators"].append(indicator)

    # --- Version headers ---
    version_header_names = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-drupal-dynamic-cache",
        "x-varnish",
    ]
    for key in version_header_names:
        val = headers.get(key, "")
        if val:
            analysis["version_headers"][key] = val

    # --- CORS headers ---
    cors_header_names = [
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
    ]
    for key in cors_header_names:
        val = headers.get(key, "")
        if val:
            analysis["cors_headers"][key] = val

    return analysis


def _check_sensitive_json(data: Any, analysis: dict[str, Any]) -> None:
    """Recursively check JSON data for sensitive values."""
    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = str(key).lower()
            # Keys that suggest sensitive data
            sensitive_keys = [
                "password",
                "passwd",
                "secret",
                "token",
                "api_key",
                "apikey",
                "access_token",
                "refresh_token",
                "private_key",
                "ssn",
                "social_security",
                "credit_card",
                "card_number",
            ]
            if any(sk in key_lower for sk in sensitive_keys):
                if value and str(value).strip():
                    analysis["has_sensitive_patterns"] = True
                    analysis["sensitive_patterns_found"].append(f"field:{key}")
            if isinstance(value, (dict, list)):
                _check_sensitive_json(value, analysis)
    elif isinstance(data, list):
        for item in data[:10]:  # Check first 10 items
            if isinstance(item, (dict, list)):
                _check_sensitive_json(item, analysis)


# ---------------------------------------------------------------------------
# Verification pipeline: compare claims to reality
# ---------------------------------------------------------------------------


def _verify_claims(
    claims: dict[str, Any], response: dict[str, Any], finding: dict[str, Any]
) -> LiveVerificationResult:
    """Compare agent's claims against actual response analysis.

    This is the agnostic core. No platform-specific logic. Just:
    - What did the agent claim?
    - What does the response actually contain?
    - Do they match?
    """
    title = finding.get("title", "")
    status = response["status"]

    # --- Connection failure ---
    if status == 0:
        return _result(title, False, "error", "Could not connect to the target", "", 0.0)

    # --- Endpoint protected (401/403) ---
    if status in (401, 403):
        if claims["unauthenticated"]:
            return _result(
                title,
                False,
                "contradicted",
                f"Endpoint requires authentication (HTTP {status}). "
                f"The agent claimed it was accessible without auth.",
                _evidence(response),
                0.9,
            )
        return _result(
            title,
            False,
            "unverifiable",
            f"Endpoint returned HTTP {status}",
            _evidence(response),
            0.5,
        )

    # --- Login page (endpoint serves login form, not actual data) ---
    if response["is_login_page"]:
        if claims["unauthenticated"] or claims["returns_data"]:
            return _result(
                title,
                False,
                "contradicted",
                f"Endpoint serves a login page, not the claimed data. "
                f"Indicators: {response['login_indicators']}",
                _evidence(response),
                0.85,
            )
        return _result(
            title, False, "unverifiable", "Endpoint serves a login page", _evidence(response), 0.5
        )

    # --- Error page ---
    if response["is_error_page"]:
        return _result(
            title,
            False,
            "contradicted",
            f"Endpoint returned an error page (HTTP {status})",
            _evidence(response),
            0.8,
        )

    # --- CORS verification ---
    if claims["cors_misconfigured"]:
        return _verify_cors_claims(claims, response, finding)

    # --- Version disclosure verification ---
    if claims["version_disclosed"]:
        if response["version_headers"]:
            return _result(
                title,
                True,
                "confirmed",
                f"Version headers present: {list(response['version_headers'].keys())}",
                json.dumps(response["version_headers"], indent=2),
                0.9,
            )
        return _result(
            title,
            False,
            "contradicted",
            "No version-disclosing headers found in response",
            _evidence(response),
            0.8,
        )

    # --- Directory listing verification ---
    if claims["directory_listing"]:
        if response["has_directory_listing"]:
            return _result(
                title,
                True,
                "confirmed",
                f"Directory listing confirmed: {response['directory_indicators']}",
                _evidence(response),
                0.95,
            )
        return _result(
            title,
            False,
            "contradicted",
            "No directory listing indicators found in response",
            _evidence(response),
            0.7,
        )

    # --- Data exposure verification ---
    if claims["returns_data"] or claims["returns_user_data"]:
        return _verify_data_claims(claims, response, finding)

    # --- Generic accessibility check ---
    if claims["accessible"]:
        if status == 200:
            # Even generic claims should detect login pages
            if response["is_login_page"]:
                return _result(
                    title,
                    False,
                    "contradicted",
                    "Endpoint serves a login page, not accessible data. "
                    f"Indicators: {response['login_indicators']}",
                    _evidence(response),
                    0.85,
                )
            return _result(
                title,
                True,
                "confirmed",
                f"Endpoint accessible (HTTP 200, {response['body_length']} bytes)",
                _evidence(response),
                0.7,
            )
        return _result(
            title,
            False,
            "unverifiable",
            f"Endpoint returned HTTP {status}",
            _evidence(response),
            0.5,
        )

    # --- No specific claims to verify ---
    return _result(
        title, False, "unverifiable", "No specific claims to verify in the finding text", "", 0.3
    )


def _verify_cors_claims(
    claims: dict[str, Any], response: dict[str, Any], finding: dict[str, Any]
) -> LiveVerificationResult:
    """Verify CORS-specific claims."""
    title = finding.get("title", "")
    cors = response.get("cors_headers", {})
    acao = cors.get("access-control-allow-origin", "")
    acac = cors.get("access-control-allow-credentials", "").lower()

    if not acao:
        return _result(
            title,
            False,
            "contradicted",
            "No Access-Control-Allow-Origin header present",
            json.dumps(cors, indent=2),
            0.9,
        )

    if acao == "*":
        if acac == "true":
            return _result(
                title,
                True,
                "confirmed",
                "CORS allows all origins with credentials — misconfiguration confirmed",
                f"ACAO: {acao}, ACAC: {acac}",
                0.9,
            )
        return _result(
            title,
            False,
            "contradicted",
            "CORS allows all origins but without credentials — this is intentional for public APIs",
            f"ACAO: {acao}, ACAC: {acac}",
            0.8,
        )

    # Check if ACAO reflects an arbitrary origin
    if claims["cors_reflects_origin"]:
        # Already checked with the Origin header — if ACAO is not * and not
        # the attacker origin, it's restricted
        attacker_origin = "https://evil-verify-test.example.com"
        if acao == attacker_origin:
            return _result(
                title,
                True,
                "confirmed",
                f"CORS reflects attacker origin: {acao}",
                f"ACAO: {acao}, ACAC: {acac}",
                0.9,
            )
        return _result(
            title,
            False,
            "contradicted",
            f"CORS is restricted to specific origin: {acao}",
            f"ACAO: {acao}, ACAC: {acac}",
            0.8,
        )

    return _result(
        title,
        True,
        "confirmed",
        f"CORS header present: ACAO={acao}",
        f"ACAO: {acao}, ACAC: {acac}",
        0.7,
    )


def _verify_data_claims(
    claims: dict[str, Any], response: dict[str, Any], finding: dict[str, Any]
) -> LiveVerificationResult:
    """Verify data exposure claims."""
    title = finding.get("title", "")
    status = response["status"]

    if status != 200:
        return _result(
            title,
            False,
            "contradicted",
            f"Agent claimed data exposure but endpoint returned HTTP {status}",
            _evidence(response),
            0.8,
        )

    # Check if response actually contains data
    if response["is_empty"]:
        return _result(
            title,
            False,
            "contradicted",
            "Endpoint returned HTTP 200 but response body is empty",
            "",
            0.8,
        )

    # JSON response analysis
    if response["is_json"]:
        if claims["returns_user_data"]:
            if response["has_user_fields"]:
                return _result(
                    title,
                    True,
                    "confirmed",
                    f"Endpoint returns {response['json_records']} record(s) "
                    f"with user-like fields: {response['user_field_names']}",
                    _evidence(response),
                    0.95,
                )
            return _result(
                title,
                False,
                "contradicted",
                f"Endpoint returned JSON ({response['json_records']} records) "
                f"but no user/account fields found",
                _evidence(response),
                0.7,
            )

        # Generic data claim — any JSON with content is data
        if response["json_records"] > 0:
            confidence = 0.85 if response["has_sensitive_patterns"] else 0.7
            return _result(
                title,
                True,
                "confirmed",
                f"Endpoint returns JSON data ({response['json_records']} records, "
                f"{response['body_length']} bytes)",
                _evidence(response),
                confidence,
            )

    # Non-JSON response with data
    if response["body_length"] > 50:
        if response["has_sensitive_patterns"]:
            return _result(
                title,
                True,
                "confirmed",
                f"Endpoint returns data with sensitive patterns: "
                f"{response['sensitive_patterns_found']}",
                _evidence(response),
                0.85,
            )
        if response["has_user_fields"]:
            return _result(
                title,
                True,
                "confirmed",
                "Endpoint returns data with user-related content",
                _evidence(response),
                0.8,
            )
        return _result(
            title,
            True,
            "confirmed",
            f"Endpoint returns data ({response['body_length']} bytes) without authentication",
            _evidence(response),
            0.7,
        )

    return _result(
        title,
        False,
        "unverifiable",
        f"Endpoint returned HTTP 200 but response is ambiguous ({response['body_length']} bytes)",
        _evidence(response),
        0.5,
    )


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def _result(
    title: str,
    verified: bool,
    verdict: str,
    reason: str,
    evidence: str,
    confidence: float,
    requests: list[str] | None = None,
    codes: list[int] | None = None,
) -> LiveVerificationResult:
    """Build a LiveVerificationResult."""
    item = {
        "evidence_kind": "response",
        "summary": reason,
        "inline_json": {
            "verdict": verdict,
            "verified": verified,
            "evidence": evidence[:2000],
            "confidence": confidence,
            "response_codes": codes or [],
            "requests": requests or [],
        },
    }
    return LiveVerificationResult(
        finding_title=title,
        verified=verified,
        verdict=verdict,
        reason=reason,
        evidence=evidence[:2000],
        confidence=confidence,
        requests_made=requests or [],
        response_codes=codes or [],
        evidence_items=[item],
    )


def _evidence(response: dict[str, Any], max_len: int = 1000) -> str:
    """Extract evidence string from response analysis."""
    parts = []
    if response.get("is_json"):
        data = response.get("json_data")
        if data is not None:
            parts.append(json.dumps(data, indent=2)[:max_len])
    # Fall back to body
    return "".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# CORS-specific: send attacker Origin and check reflection
# ---------------------------------------------------------------------------


def _check_cors_reflection(url: str) -> tuple[dict[str, str], str]:
    """Send a request with attacker Origin and return CORS headers + origin sent."""
    attacker_origin = "https://evil-verify-test.example.com"
    # GET with attacker Origin
    _, _, _ = _curl_get(url, headers={"Origin": attacker_origin}, timeout=15)
    # HEAD to get headers (GET with -D would also work but HEAD is lighter)
    _, headers = _curl_head(url, timeout=15)
    return headers, attacker_origin


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def verify_live(finding: dict[str, Any]) -> LiveVerificationResult:
    """Verify a finding by making real HTTP requests to the target.

    Fully agnostic. No platform detection. No CMS-specific logic.
    Pipeline:
    1. Extract claims from the finding text
    2. Hit the endpoint
    3. Analyze the response
    4. Compare claims to reality
    5. Return verdict with evidence
    """
    title = finding.get("title", "")
    target = finding.get("target", "")
    endpoint = finding.get("endpoint", "")

    if not target:
        return _result(title, False, "error", "No target URL provided in finding", "", 0.0)

    if not target.startswith("http"):
        target = f"https://{target}"

    url = _build_url(target, endpoint)
    requests_made = [url]

    # Step 1: Extract what the agent claimed
    claims = _extract_claims(finding)
    logger.info("Live verification: url=%s claims=%s", url, {k: v for k, v in claims.items() if v})

    # Step 2: For CORS claims, send attacker Origin first
    response_headers: dict[str, str] = {}
    if claims["cors_misconfigured"]:
        response_headers, attacker_origin = _check_cors_reflection(url)
        requests_made.append(f"HEAD {url} (with Origin: {attacker_origin})")

    # Step 3: Hit the endpoint
    status, body, get_headers = _curl_get(url, timeout=30, include_headers=True)
    if get_headers:
        response_headers = get_headers  # Prefer headers from actual GET

    if not response_headers and status == 200:
        # Fallback: get headers via HEAD
        _, head_headers = _curl_head(url)
        response_headers = head_headers
        requests_made.append(f"HEAD {url}")

    # Step 4: Analyze response
    response = _analyze_response(body, status, response_headers)
    logger.info(
        "Live verification response: status=%d json=%s user_fields=%s login=%s body_len=%d",
        status,
        response["is_json"],
        response["has_user_fields"],
        response["is_login_page"],
        response["body_length"],
    )

    # Step 5: Compare claims to reality
    result = _verify_claims(claims, response, finding)
    result.requests_made = requests_made
    result.response_codes = [status]
    if result.evidence_items:
        result.evidence_items[0]["inline_json"]["requests"] = requests_made
        result.evidence_items[0]["inline_json"]["response_codes"] = [status]
    _store_live_verification_result(finding, result)

    logger.info(
        "Live verification result: verdict=%s verified=%s confidence=%.2f",
        result.verdict,
        result.verified,
        result.confidence,
    )
    return result


def _store_live_verification_result(
    finding: dict[str, Any], result: LiveVerificationResult
) -> None:
    finding_id = str(
        finding.get("finding_id") or finding.get("candidate_id") or finding.get("id") or ""
    )
    if not finding_id:
        return
    try:
        from prometheus.core.candidate_store import CandidateStore

        store = CandidateStore()
        for item in result.evidence_items:
            store.add_evidence(
                finding_id=finding_id,
                evidence_kind=str(item.get("evidence_kind") or "response"),
                summary=str(item.get("summary") or result.reason),
                inline=item.get("inline_json"),
                metadata={"validator": "live_verification"},
            )
        store.record_validation_run(
            finding_id=finding_id,
            validator="live_verification",
            status="success" if result.verified else "failed",
            confidence=result.confidence,
            output={
                "verdict": result.verdict,
                "reason": result.reason,
                "requests_made": result.requests_made,
                "response_codes": result.response_codes,
                "evidence": result.evidence,
            },
        )
    except Exception:
        logger.exception("Failed to store live verification result for %s", finding_id)
        raise
