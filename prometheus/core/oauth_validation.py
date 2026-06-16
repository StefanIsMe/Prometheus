"""OAuth and PKCE Validation Module for Prometheus.

Validates OAuth 2.0 and OpenID Connect configurations for security issues,
including PKCE downgrade attacks, missing PKCE enforcement, and metadata
inconsistencies.

This module can be used standalone or integrated into the Prometheus
validation pipeline to pre-validate OAuth findings before filing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import ssl
import urllib.parse
import urllib.request
import base64
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class OAuthValidationResult:
    """Result of validating an OAuth/OIDC endpoint."""

    target: str
    finding_type: str  # 'pkce_downgrade', 'missing_pkce_enforcement', 'metadata_mismatch', etc.
    validated: bool
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    confidence: float  # 0.0-1.0
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class OIDCConfig:
    """Parsed OpenID Connect discovery document."""

    issuer: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    code_challenge_methods_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    scopes_supported: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    fetch_error: str = ""


@dataclass
class PKCETestResult:
    """Result of testing PKCE behavior on an endpoint."""

    method: str  # 'plain', 'S256', 'none', 'invalid'
    http_status: int = 0
    accepted: bool = False
    error_code: str = ""
    error_message: str = ""
    response_snippet: str = ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_CTX = ssl.create_default_context()
_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"


def _http_get(url: str, timeout: int = 30) -> tuple[int, dict, str]:
    """Make an HTTP GET request. Returns (status, headers, body)."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e)


def _http_post(url: str, data: dict, timeout: int = 30) -> tuple[int, dict, str]:
    """Make an HTTP POST request with form data. Returns (status, headers, body)."""
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": _USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e)


# ---------------------------------------------------------------------------
# OIDC Discovery
# ---------------------------------------------------------------------------


def fetch_oidc_config(base_url: str) -> OIDCConfig:
    """Fetch and parse the OpenID Connect discovery document.

    Args:
        base_url: The base URL of the authorization server (e.g., https://auth.example.com)

    Returns:
        OIDCConfig with parsed fields.
    """
    # Normalize URL
    base_url = base_url.rstrip("/")
    discovery_url = f"{base_url}/.well-known/openid-configuration"

    # Also try the issuer path if base doesn't work
    status, _, body = _http_get(discovery_url)

    if status != 200:
        # Try with /oauth2 path (some providers)
        alt_url = f"{base_url}/.well-known/oauth-authorization-server"
        status, _, body = _http_get(alt_url)

    if status != 200:
        return OIDCConfig(fetch_error=f"HTTP {status} fetching {discovery_url}")

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        return OIDCConfig(fetch_error=f"Invalid JSON: {e}")

    return OIDCConfig(
        issuer=data.get("issuer", ""),
        authorization_endpoint=data.get("authorization_endpoint", ""),
        token_endpoint=data.get("token_endpoint", ""),
        code_challenge_methods_supported=data.get("code_challenge_methods_supported", []),
        response_types_supported=data.get("response_types_supported", []),
        scopes_supported=data.get("scopes_supported", []),
        raw=data,
    )


# ---------------------------------------------------------------------------
# PKCE value generation
# ---------------------------------------------------------------------------


def generate_pkce_pair() -> tuple[str, str, str]:
    """Generate a PKCE code_verifier, plain challenge, and S256 challenge.

    Returns:
        (code_verifier, code_challenge_plain, code_challenge_s256)
    """
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    code_challenge_plain = code_verifier
    code_challenge_s256 = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return code_verifier, code_challenge_plain, code_challenge_s256


# ---------------------------------------------------------------------------
# Authorize endpoint testing
# ---------------------------------------------------------------------------


def test_authorize_endpoint(
    authorize_url: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str = "",
    code_challenge_method: str = "",
    scope: str = "openid profile email",
) -> PKCETestResult:
    """Test the /authorize endpoint with specific PKCE parameters.

    Args:
        authorize_url: The authorization endpoint URL
        client_id: OAuth client_id to use
        redirect_uri: Redirect URI
        code_challenge: PKCE code challenge (empty = no PKCE)
        code_challenge_method: 'plain', 'S256', or empty
        scope: OAuth scope string

    Returns:
        PKCETestResult with the test outcome.
    """
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": "prometheus_pkce_test",
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
    if code_challenge_method:
        params["code_challenge_method"] = code_challenge_method

    url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
    status, headers, body = _http_get(url)

    # Determine if the request was accepted (login page shown) vs rejected (error)
    body_lower = body.lower()
    has_login = any(kw in body_lower for kw in ["login", "sign in", "password", "email"])
    _has_error = any(  # noqa: F841  — kept for future assertion hooks
        kw in body_lower
        for kw in ["invalid_request", "unsupported_response_type", "invalid_client"]
    )
    is_error_page = status >= 400 and not has_login

    method = code_challenge_method if code_challenge_method else "none"
    return PKCETestResult(
        method=method,
        http_status=status,
        accepted=has_login and status == 200,
        error_code="error_page" if is_error_page else "",
        error_message=body[:200] if is_error_page else "",
    )


# ---------------------------------------------------------------------------
# Token endpoint testing
# ---------------------------------------------------------------------------


def test_token_endpoint(
    token_url: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str = "",
    include_verifier: bool = True,
) -> PKCETestResult:
    """Test the token endpoint with a fake authorization code.

    Args:
        token_url: The token endpoint URL
        client_id: OAuth client_id
        redirect_uri: Redirect URI
        code_verifier: PKCE code verifier to send
        include_verifier: Whether to include code_verifier at all

    Returns:
        PKCETestResult with the error response pattern.
    """
    data = {
        "grant_type": "authorization_code",
        "code": "prometheus_fake_code_for_validation",
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    if include_verifier and code_verifier:
        data["code_verifier"] = code_verifier

    status, _, body = _http_post(token_url, data)

    error_code = ""
    error_message = ""
    try:
        resp = json.loads(body)
        error_code = resp.get("error", {}).get("code", "")
        error_message = resp.get("error", {}).get("message", "")
    except (json.JSONDecodeError, AttributeError):
        error_message = body[:200]

    return PKCETestResult(
        method="with_verifier" if include_verifier else "without_verifier",
        http_status=status,
        accepted=False,  # Fake code should always fail
        error_code=error_code,
        error_message=error_message,
        response_snippet=body[:500],
    )


# ---------------------------------------------------------------------------
# Full PKCE downgrade validation
# ---------------------------------------------------------------------------


def validate_pkce_downgrade(
    base_url: str,
    client_id: str = "",
    redirect_uri: str = "",
    authorize_endpoint: str = "",
    token_endpoint: str = "",
) -> OAuthValidationResult:
    """Full PKCE downgrade validation pipeline.

    Steps:
    1. Fetch OIDC discovery document
    2. Check code_challenge_methods_supported for 'plain'
    3. Test /authorize endpoint with plain, S256, no PKCE, invalid method
    4. Test token endpoint with/without code_verifier
    5. Cross-reference with RFC 9700 requirements

    Args:
        base_url: Authorization server base URL
        client_id: OAuth client_id (will try to discover if empty)
        redirect_uri: Redirect URI for testing
        authorize_endpoint: Override authorize URL (default: from discovery)
        token_endpoint: Override token URL (default: from discovery)

    Returns:
        OAuthValidationResult with full validation outcome.
    """
    evidence = []
    details: dict[str, Any] = {}
    severity = "info"
    validated = False

    # Step 1: Fetch OIDC config
    config = fetch_oidc_config(base_url)
    if config.fetch_error:
        return OAuthValidationResult(
            target=base_url,
            finding_type="pkce_downgrade",
            validated=False,
            severity="info",
            confidence=0.0,
            error=f"Failed to fetch OIDC config: {config.fetch_error}",
        )

    details["issuer"] = config.issuer
    details["code_challenge_methods_supported"] = config.code_challenge_methods_supported
    evidence.append(f"OIDC discovery document fetched from {base_url}")
    evidence.append(f"Issuer: {config.issuer}")
    evidence.append(f"code_challenge_methods_supported: {config.code_challenge_methods_supported}")

    # Determine endpoints
    auth_url = authorize_endpoint or config.authorization_endpoint
    tok_url = token_endpoint or config.token_endpoint

    # Step 2: Check if 'plain' is advertised
    plain_advertised = "plain" in config.code_challenge_methods_supported
    s256_advertised = "S256" in config.code_challenge_methods_supported

    if not plain_advertised:
        evidence.append("PASS: 'plain' NOT advertised in discovery document")
        return OAuthValidationResult(
            target=base_url,
            finding_type="pkce_downgrade",
            validated=False,
            severity="info",
            confidence=0.9,
            evidence=evidence,
            details=details,
            error="No vulnerability: 'plain' PKCE method is not advertised",
        )

    evidence.append("FINDING: 'plain' IS advertised in code_challenge_methods_supported")
    severity = "medium"

    # Step 3: Generate PKCE values
    verifier, challenge_plain, challenge_s256 = generate_pkce_pair()
    details["test_verifier"] = verifier

    # Step 4: Test authorize endpoint
    if auth_url:
        # Use a common client_id pattern if none provided
        test_client_id = client_id or "test_client_id"
        test_redirect = redirect_uri or "https://example.com/callback"

        # Test with plain
        result_plain = test_authorize_endpoint(
            auth_url, test_client_id, test_redirect, challenge_plain, "plain"
        )
        evidence.append(
            f"Authorize with plain PKCE: HTTP {result_plain.http_status}, accepted={result_plain.accepted}"
        )

        # Test with S256
        result_s256 = test_authorize_endpoint(
            auth_url, test_client_id, test_redirect, challenge_s256, "S256"
        )
        evidence.append(
            f"Authorize with S256 PKCE: HTTP {result_s256.http_status}, accepted={result_s256.accepted}"
        )

        # Test without PKCE
        result_none = test_authorize_endpoint(auth_url, test_client_id, test_redirect)
        evidence.append(
            f"Authorize without PKCE: HTTP {result_none.http_status}, accepted={result_none.accepted}"
        )

        # Test with invalid method
        result_invalid = test_authorize_endpoint(
            auth_url, test_client_id, test_redirect, "test123", "invalid"
        )
        evidence.append(
            f"Authorize with invalid method: HTTP {result_invalid.http_status}, accepted={result_invalid.accepted}"
        )

        details["authorize_tests"] = {
            "plain": {"status": result_plain.http_status, "accepted": result_plain.accepted},
            "s256": {"status": result_s256.http_status, "accepted": result_s256.accepted},
            "none": {"status": result_none.http_status, "accepted": result_none.accepted},
            "invalid": {"status": result_invalid.http_status, "accepted": result_invalid.accepted},
        }

        if result_plain.accepted:
            evidence.append("FINDING: /authorize endpoint accepts plain PKCE method")

        if result_none.accepted:
            evidence.append(
                "FINDING: /authorize endpoint accepts requests without PKCE (no enforcement)"
            )

    # Step 5: Test token endpoint
    if tok_url:
        test_client_id = client_id or "test_client_id"
        test_redirect = redirect_uri or "https://example.com/callback"

        result_with = test_token_endpoint(tok_url, test_client_id, test_redirect, verifier, True)
        result_without = test_token_endpoint(tok_url, test_client_id, test_redirect, "", False)

        evidence.append(
            f"Token with verifier: HTTP {result_with.http_status}, error={result_with.error_code}"
        )
        evidence.append(
            f"Token without verifier: HTTP {result_without.http_status}, error={result_without.error_code}"
        )

        details["token_tests"] = {
            "with_verifier": {"status": result_with.http_status, "error": result_with.error_code},
            "without_verifier": {
                "status": result_without.http_status,
                "error": result_without.error_code,
            },
        }

        # If both return same error, the proxy may not check PKCE at all
        if result_with.error_code == result_without.error_code:
            evidence.append("NOTE: Token endpoint returns same error with/without code_verifier")

    # Step 6: Compute verdict
    # Validated = plain advertised AND token endpoint confirmed accepting plain
    # with a REAL authorization code (not a fake code).
    #
    # CRITICAL: /authorize accepting plain is NOT evidence. The /authorize
    # endpoint is a UI redirect that shows a login page for any valid-looking
    # request. Real PKCE validation happens at the token exchange endpoint.
    # Without a real auth code (requires user login), we cannot prove the
    # token endpoint accepts plain code_verifier.
    #
    # Therefore: metadata-only findings are INFORMATIONAL, not reportable.
    if plain_advertised:
        # Check if token endpoint testing revealed anything
        token_tests = details.get("token_tests", {})
        token_with = token_tests.get("with_verifier", {})
        token_without = token_tests.get("without_verifier", {})

        # If both return the same error, we can't distinguish PKCE behavior
        # (fake code always fails before PKCE is checked)
        if token_with.get("error") == token_without.get("error"):
            validated = False
            confidence = 0.3
            severity = "info"
            evidence.append(
                "NOT REPORTABLE: Token endpoint returns same error with/without "
                "code_verifier (fake code rejected before PKCE check). "
                "Cannot confirm token endpoint accepts plain PKCE without a real "
                "authorization code from a completed user login flow."
            )
        else:
            # Different errors MIGHT indicate PKCE validation difference,
            # but still needs a real code to confirm
            validated = False
            confidence = 0.5
            severity = "low"
            evidence.append(
                "LOW CONFIDENCE: Token endpoint returned different errors for "
                "with/without verifier, but used fake code. Needs real auth code "
                "from completed OAuth flow to confirm PKCE bypass."
            )

        if s256_advertised:
            evidence.append("INFO: S256 also advertised (correct behavior)")
        else:
            evidence.append("FINDING: S256 NOT advertised -- only plain supported")
            severity = "low" if severity == "info" else severity

        evidence.append(
            "AUTO-REPORT BLOCKER: PKCE plain findings are NOT auto-reportable. "
            "To report, must demonstrate full token exchange with real auth code "
            "using plain code_verifier. See pkce_downgrade.md skill for details."
        )

    # RFC 9700 reference
    evidence.append("REFERENCE: RFC 9700 S2.1.2 - 'Currently, S256 is the only such method'")
    evidence.append("REFERENCE: RFC 7636 S4.2 - plain method = code_challenge == code_verifier")

    return OAuthValidationResult(
        target=base_url,
        finding_type="pkce_downgrade",
        validated=validated,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        details=details,
        remediation=(
            "1. Remove 'plain' from code_challenge_methods_supported. "
            "2. Only advertise and accept 'S256'. "
            "3. Enforce PKCE for all authorization code flows. "
            "4. Reject requests missing code_challenge with invalid_request error."
        ),
        references=[
            "https://datatracker.ietf.org/doc/html/rfc9700",
            "https://datatracker.ietf.org/doc/html/rfc7636",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-4144",
        ],
    )


# ---------------------------------------------------------------------------
# Additional OAuth checks
# ---------------------------------------------------------------------------


def validate_missing_pkce_enforcement(
    base_url: str,
    client_id: str = "",
    redirect_uri: str = "",
) -> OAuthValidationResult:
    """Check if PKCE is enforced (requests without PKCE are rejected)."""
    config = fetch_oidc_config(base_url)
    if config.fetch_error:
        return OAuthValidationResult(
            target=base_url,
            finding_type="missing_pkce_enforcement",
            validated=False,
            severity="info",
            confidence=0.0,
            error=f"Failed to fetch OIDC config: {config.fetch_error}",
        )

    auth_url = config.authorization_endpoint
    if not auth_url:
        return OAuthValidationResult(
            target=base_url,
            finding_type="missing_pkce_enforcement",
            validated=False,
            severity="info",
            confidence=0.0,
            error="No authorization_endpoint in discovery document",
        )

    test_client_id = client_id or "test_client_id"
    test_redirect = redirect_uri or "https://example.com/callback"

    result = test_authorize_endpoint(auth_url, test_client_id, test_redirect)

    if result.accepted:
        return OAuthValidationResult(
            target=base_url,
            finding_type="missing_pkce_enforcement",
            validated=True,
            severity="medium",
            confidence=0.7,
            evidence=[
                f"Authorize endpoint accepts requests without PKCE parameters",
                f"HTTP {result.http_status} with login page shown",
                "Per RFC 9700 and OAuth 2.1, PKCE should be mandatory for all clients",
            ],
            remediation="Enforce PKCE by requiring code_challenge on all authorization requests.",
            references=["https://datatracker.ietf.org/doc/html/rfc9700"],
        )

    return OAuthValidationResult(
        target=base_url,
        finding_type="missing_pkce_enforcement",
        validated=False,
        severity="info",
        confidence=0.8,
        evidence=[f"Authorize endpoint returned HTTP {result.http_status} without PKCE"],
        error="PKCE appears to be enforced or endpoint rejected the request",
    )


def check_metadata_consistency(base_url: str) -> OAuthValidationResult:
    """Check if discovery document metadata is consistent with actual behavior.

    Specifically checks if advertised PKCE methods are actually supported.
    """
    config = fetch_oidc_config(base_url)
    if config.fetch_error:
        return OAuthValidationResult(
            target=base_url,
            finding_type="metadata_mismatch",
            validated=False,
            severity="info",
            confidence=0.0,
            error=f"Failed to fetch OIDC config: {config.fetch_error}",
        )

    evidence = []
    issues = []

    # Check PKCE methods
    methods = config.code_challenge_methods_supported
    if "plain" in methods:
        issues.append("Discovery advertises 'plain' PKCE (RFC 9700 recommends S256 only)")
        evidence.append(f"code_challenge_methods_supported: {methods}")

    # Check for other common metadata issues
    if not config.token_endpoint:
        issues.append("Missing token_endpoint in discovery document")
    if not config.authorization_endpoint:
        issues.append("Missing authorization_endpoint in discovery document")

    if issues:
        return OAuthValidationResult(
            target=base_url,
            finding_type="metadata_mismatch",
            validated=True,
            severity="low" if len(issues) == 1 and "plain" in str(issues) else "info",
            confidence=0.8,
            evidence=evidence + [f"Issue: {i}" for i in issues],
            details={"issues": issues, "config": config.raw},
        )

    return OAuthValidationResult(
        target=base_url,
        finding_type="metadata_mismatch",
        validated=False,
        severity="info",
        confidence=0.9,
        evidence=["Discovery document metadata appears consistent"],
    )


# ---------------------------------------------------------------------------
# CLI entry point for standalone testing
# ---------------------------------------------------------------------------


def run_full_audit(base_url: str, client_id: str = "", redirect_uri: str = "") -> dict[str, Any]:
    """Run a full OAuth security audit against a target.

    Args:
        base_url: Authorization server base URL
        client_id: OAuth client_id for testing
        redirect_uri: Redirect URI for testing

    Returns:
        Dict with all validation results.
    """
    results = {}

    # 1. PKCE Downgrade
    logger.info("Running PKCE downgrade validation against %s", base_url)
    results["pkce_downgrade"] = validate_pkce_downgrade(base_url, client_id, redirect_uri)

    # 2. Missing PKCE Enforcement
    logger.info("Running missing PKCE enforcement check against %s", base_url)
    results["missing_pkce_enforcement"] = validate_missing_pkce_enforcement(
        base_url, client_id, redirect_uri
    )

    # 3. Metadata Consistency
    logger.info("Running metadata consistency check against %s", base_url)
    results["metadata_consistency"] = check_metadata_consistency(base_url)

    return results


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage: python oauth_validation.py <base_url> [client_id] [redirect_uri]")
        print(
            "Example: python oauth_validation.py https://auth.example.com app_example_client_id https://example.com/api/auth/callback"
        )
        sys.exit(1)

    url = sys.argv[1]
    cid = sys.argv[2] if len(sys.argv) > 2 else ""
    ruri = sys.argv[3] if len(sys.argv) > 3 else ""

    print("=" * 70)
    print(f"OAuth Security Audit: {url}")
    print("=" * 70)

    audit = run_full_audit(url, cid, ruri)

    for name, result in audit.items():
        print(f"\n{'=' * 40}")
        print(f"Check: {name}")
        print(f"  Validated: {result.validated}")
        print(f"  Severity:  {result.severity}")
        print(f"  Confidence: {result.confidence}")
        if result.error:
            print(f"  Error: {result.error}")
        for ev in result.evidence:
            print(f"  - {ev}")
        if result.remediation:
            print(f"  Remediation: {result.remediation}")
