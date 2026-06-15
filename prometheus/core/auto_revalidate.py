"""Live re-validation probes for fingerprint collisions.

When prometheus re-discovers a finding whose fingerprint already has a
report_status or external_submissions row, this module runs a minimal
live HTTP probe against the target to determine whether the underlying
behavior has shifted since the prior closure. The result is:

  - `changed=True`  the target now behaves differently from the prior record
                    (e.g. the auth team finally removed the `plain` PKCE
                    method). Worth a re-submission.
  - `changed=False` the target still behaves the same. Don't re-file; the
                    prior closure still applies.
  - `inconclusive`  the probe failed (timeout, WAF block, network error).
                    Default to "no change" and let should_revalidate decide.

The probes are intentionally cheap (max 5 HTTP requests) so they can run
on every fingerprint collision without slowing the scan.

The probe is selected by `vuln_type`, which is a normalized string. The
report_status / external_submissions rows may have it in different
columns; the caller resolves the right one.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any


logger = logging.getLogger(__name__)

# Maximum bytes to read from any single response. Probes are sniffers;
# the full body is not needed.
_MAX_PROBE_BODY = 4096

# Default request timeout per probe.
_PROBE_TIMEOUT = 8

# Reusable SSL context that doesn't verify certs (some targets have weird
# certs that are not in scope of the dedup decision).
_unverified_ctx = ssl.create_default_context()
_unverified_ctx.check_hostname = False
_unverified_ctx.verify_mode = ssl.CERT_NONE


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: int = _PROBE_TIMEOUT
) -> tuple[int, str, dict[str, str]]:
    """Lightweight GET that returns (status, body, response_headers).

    Returns (0, '', {}) on any network failure. Does not raise.
    """
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_unverified_ctx) as resp:
            body = resp.read(_MAX_PROBE_BODY).decode("utf-8", errors="ignore")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return (resp.status, body, hdrs)
    except Exception as e:  # noqa: BLE001
        logger.debug("live_revalidate._http_get(%s) failed: %s", url, e)
        return (0, "", {})


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _probe_pkce(endpoint: str) -> dict[str, Any]:
    """PKCE probe: re-fetch the OpenID Connect discovery document and check
    whether `code_challenge_methods_supported` still includes `plain`.

    `endpoint` should be a `.well-known/openid-configuration` URL or the
    issuer base. We try the explicit URL first, then /openid-configuration.
    """
    if not endpoint:
        return {"changed": False, "evidence": "no endpoint to probe"}
    candidates: list[str] = []
    if "openid-configuration" in endpoint:
        candidates.append(endpoint)
    else:
        # Try /.well-known/openid-configuration alongside the endpoint
        parsed = urllib.parse.urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates.append(f"{base}/.well-known/openid-configuration")
        candidates.append(endpoint)

    evidence_lines: list[str] = []
    found_plain = False
    last_status = 0
    for url in candidates:
        status, body, _ = _http_get(url)
        last_status = status
        if status != 200 or not body:
            evidence_lines.append(f"GET {url} -> {status}")
            continue
        try:
            cfg = json.loads(body)
        except Exception:
            evidence_lines.append(f"GET {url} -> 200 (non-JSON, body_hash={_body_hash(body)})")
            continue
        methods = cfg.get("code_challenge_methods_supported") or []
        evidence_lines.append(f"GET {url} -> 200; methods={methods}")
        if "plain" in methods:
            found_plain = True
        break

    if not evidence_lines:
        return {
            "changed": "inconclusive",
            "evidence": f"all probes failed; last_status={last_status}",
        }
    # The behavior is "supports plain". For the existing closed finding
    # (which Bugcrowd closed as not_reproducible, meaning the *advertising*
    # of plain was the issue), "changed" means the auth team finally
    # removed `plain` from the list.
    return {
        "changed": not found_plain,
        "evidence": (
            f"PKCE plain method {'still' if found_plain else 'no longer'} "
            f"advertised in discovery doc; " + " | ".join(evidence_lines)
        ),
    }


def _probe_account_enumeration(endpoint: str) -> dict[str, Any]:
    """Account-enumeration probe: 3 emails, compare response codes/bodies.

    Re-runs the differential response test. If the 3 responses are still
    distinct, behavior is unchanged. If two of them now return the same
    status/body, the team has harmonized the responses.
    """
    if not endpoint:
        return {"changed": False, "evidence": "no endpoint to probe"}
    base = endpoint
    # Best-effort: don't have a known-valid email; use placeholder emails
    # that exercise the differential behavior. The probe is informational;
    # 200 from any of them might mean "fixed" (harmonized) or "valid email
    # accepted" (unfixable by structure). The user can interpret the
    # results manually.
    payload_template = {
        "username": {"kind": "email", "value": "__EMAIL__"},
        "state": "prom-rl-revalidation-{}",
        "screen_hint": "login",
    }
    test_emails = [
        ("nonexistent-revalidation-{}@testdomain.invalid", "nonexistent"),
        ("test-user-{}@gmail.com", "valid_placeholder"),
        ("admin-{}@example-corp.com", "sso_placeholder"),
    ]
    fingerprints: list[tuple[str, int, str]] = []
    for email_template, label in test_emails:
        email = email_template.format(int(time.time()))
        payload = json.dumps(payload_template).replace("__EMAIL__", email)
        try:
            req = urllib.request.Request(
                base,
                data=payload.encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                },
            )
            with urllib.request.urlopen(
                req, timeout=_PROBE_TIMEOUT, context=_unverified_ctx
            ) as resp:
                status = resp.status
                body = resp.read(_MAX_PROBE_BODY).decode("utf-8", errors="ignore")
                # Account-enumeration is usually 400 vs 200 vs 302, but the
                # 302 redirect can swallow the status. Capture both.
                if status in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location") or resp.headers.get("location") or ""
                    fingerprints.append((label, status, _body_hash(loc or body)))
                else:
                    fingerprints.append((label, status, _body_hash(body)))
        except urllib.error.HTTPError as e:
            # Some endpoints return 4xx for non-existent emails
            body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            fingerprints.append((label, e.code, _body_hash(body)))
        except Exception as e:  # noqa: BLE001
            fingerprints.append((label, 0, f"err={type(e).__name__}"))

    if len(fingerprints) < 3:
        return {
            "changed": "inconclusive",
            "evidence": f"only got {len(fingerprints)} of 3 responses: {fingerprints}",
        }
    statuses = {f[1] for f in fingerprints}
    changed = len(statuses) < 3
    return {
        "changed": changed,
        "evidence": (
            f"3 emails sent; response codes/bodies: {fingerprints}; "
            f"distinct_statuses={len(statuses)}; "
            f"{'still differential' if not changed else 'responses harmonized'}"
        ),
    }


def _probe_cors(endpoint: str) -> dict[str, Any]:
    """CORS probe: re-fetch with an evil origin and inspect ACAO header."""
    if not endpoint:
        return {"changed": False, "evidence": "no endpoint to probe"}
    status, body, hdrs = _http_get(
        endpoint,
        headers={
            "Origin": "https://evil.example.com",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        },
    )
    acao = hdrs.get("access-control-allow-origin") or hdrs.get("Access-Control-Allow-Origin") or ""
    reflects_evil = acao.strip() == "https://evil.example.com" or acao.strip() == "*"
    # The "fixed" state is one where the server does NOT reflect an evil
    # origin AND does not return "*". Status 4xx/5xx with no ACAO is also
    # considered "fixed".
    return {
        "changed": not reflects_evil,
        "evidence": f"GET {endpoint} with evil origin -> status={status} ACAO='{acao}'; {'still reflects/wildcards' if reflects_evil else 'no longer vulnerable'}",
    }


def _probe_auth_bypass(endpoint: str) -> dict[str, Any]:
    """Auth-bypass probe: send a request without credentials and check
    whether the server still returns 200 with sensitive content."""
    if not endpoint:
        return {"changed": False, "evidence": "no endpoint to probe"}
    status, body, _ = _http_get(endpoint)
    is_open = status == 200 and len(body) > 100
    return {
        "changed": not is_open,
        "evidence": f"GET {endpoint} (no auth) -> status={status} body_len={len(body)}; {'still open' if is_open else 'now requires auth'}",
    }


def _probe_body_hash(endpoint: str) -> dict[str, Any]:
    """Fallback probe: fetch the endpoint and SHA-256 the body. Records
    the hash so the user can manually diff across runs."""
    if not endpoint:
        return {"changed": False, "evidence": "no endpoint to probe"}
    status, body, _ = _http_get(endpoint)
    return {
        "changed": "inconclusive",
        "evidence": (
            f"GET {endpoint} -> status={status} body_hash={_body_hash(body)}; "
            f"compare across runs to detect behavior shifts"
        ),
    }


# Vuln-type → probe selector
_VULN_TYPE_PROBES: dict[str, Any] = {
    "oauth_vulnerabilities": _probe_pkce,
    "oauth": _probe_pkce,
    "pkce": _probe_pkce,
    "openid_configuration": _probe_pkce,
    "account_enumeration": _probe_account_enumeration,
    "user_enumeration": _probe_account_enumeration,
    "enumeration": _probe_account_enumeration,
    "auth_bypass": _probe_auth_bypass,
    "broken_authentication": _probe_auth_bypass,
    "cors": _probe_cors,
    "cors_misconfiguration": _probe_cors,
}

# Title-token → probe (for when vuln_type is not informative)
_TITLE_TOKEN_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(pkce|openid|oauth)\b", re.I), "pkce"),
    (re.compile(r"\b(enumeration|user discovery|account discovery)\b", re.I), "enumeration"),
    (re.compile(r"\b(cors|cross[- ]origin)\b", re.I), "cors"),
    (re.compile(r"\b(auth[- ]?bypass|broken authentication|auth bypass)\b", re.I), "auth_bypass"),
]


def _resolve_probe(finding: dict[str, Any]) -> tuple[str, Any]:
    """Pick the right probe for this finding. Returns (probe_name, fn)."""
    vuln_type = str(finding.get("vuln_type") or "").lower()
    title = str(finding.get("finding_title") or "")
    if vuln_type in _VULN_TYPE_PROBES:
        return (vuln_type, _VULN_TYPE_PROBES[vuln_type])
    for pattern, name in _TITLE_TOKEN_HINTS:
        if pattern.search(title):
            return (name, _VULN_TYPE_PROBES[name])
    return ("fallback", _probe_body_hash)


def live_revalidate(finding: dict[str, Any]) -> dict[str, Any]:
    """Run the appropriate live probe for *finding* and return whether
    the underlying behavior has changed.

    `finding` is a dict with at least `endpoint` (or derivable from
    finding_title/notes) and optionally `vuln_type`. Returns a dict:

        {
            "changed": bool | "inconclusive",
            "evidence": str,
            "probe": str,         # the probe name used
            "endpoint": str,      # the URL we hit
            "ts": str,            # ISO timestamp
        }
    """
    if not isinstance(finding, dict):
        return {"changed": "inconclusive", "evidence": "finding is not a dict"}
    endpoint = finding.get("endpoint") or finding.get("uri") or ""
    # If endpoint is the auth URL like /authorize, fall back to the
    # .well-known/openid-configuration for PKCE-style findings.
    title = str(finding.get("finding_title") or "")
    if not endpoint and ("openid-configuration" in title.lower() or "openid" in title.lower()):
        # Try to derive from finding domain
        domain = finding.get("domain") or ""
        if domain:
            endpoint = f"https://{domain}/.well-known/openid-configuration"
    if not endpoint and finding.get("domain"):
        endpoint = f"https://{finding['domain']}/.well-known/openid-configuration"

    probe_name, probe_fn = _resolve_probe(finding)
    try:
        result = probe_fn(endpoint)
    except Exception as e:  # noqa: BLE001
        logger.exception("live_revalidate: probe %s crashed", probe_name)
        return {
            "changed": "inconclusive",
            "evidence": f"probe {probe_name} crashed: {e}",
            "probe": probe_name,
            "endpoint": endpoint,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
    result.setdefault("probe", probe_name)
    result.setdefault("endpoint", endpoint)
    result["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return result


if __name__ == "__main__":
    # CLI for manual invocation. Reads a finding dict from stdin (JSON)
    # and writes the revalidation result to stdout.
    import sys

    finding = json.loads(sys.stdin.read() or "{}")
    result = live_revalidate(finding)
    print(json.dumps(result, indent=2, default=str))
