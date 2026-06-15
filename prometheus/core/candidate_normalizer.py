"""Normalize raw scanner and agent findings into canonical candidates."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from prometheus.core.candidate_fingerprint import fingerprint_candidate
from prometheus.core.candidate_schema import FindingCandidate

_REJECT_RULES: tuple[tuple[str, str], ...] = (
    (
        r"missing\s+(security\s+)?(header|csp|hsts|x[-\s]?frame|content[-\s]?type|referrer|x\s+frame)",
        "missing security header without exploit path",
    ),
    (
        r"internal\s+(host|hostname|ip|address).*(disclos|leak|expos|found)",
        "internal hostname disclosure without exploit chain",
    ),
    (
        r"(version|banner|fingerprint).*?(disclos|leak|expos|found)",
        "generic version disclosure without exploit chain",
    ),
    (r"cors.*?(options|preflight).*?(only|no readable|no data)", "CORS preflight only evidence"),
    (
        r"source\s*map.*?(only|no exploit|visibility)",
        "source map without sensitive or exploitable path",
    ),
    (r"rate\s*limit.*?(low value|non-sensitive|public)", "rate limit issue on low value endpoint"),
    (
        r"public\s+(api|information|asset|documentation)",
        "public information with no security impact",
    ),
)

_VULN_TYPE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"idor|insecure direct object|object reference", "idor"),
    (r"auth(entication|orization)?\s*bypass|access control bypass", "auth_bypass"),
    (r"enumeration|user discovery|account discovery", "account_enumeration"),
    (r"ssrf|server side request forgery", "ssrf"),
    (r"cors", "cors"),
    (r"unauthenticated|exposed endpoint|public endpoint", "exposed_unauthenticated_endpoint"),
    (r"source\s*map|bundle leak|client bundle", "source_map_or_bundle_leak"),
)


def normalize_finding(
    raw: dict[str, Any],
    *,
    domain: str,
    scan_id: str,
    source_tool: str = "agent",
    source_type: str = "agent_finding",
) -> FindingCandidate:
    """Return a canonical candidate from one raw finding dict."""
    domain_clean = _domain_from_url(domain) or domain
    title = str(
        raw.get("title") or raw.get("finding_title") or raw.get("name") or "Untitled finding"
    ).strip()
    endpoint = _first_present(raw, "endpoint", "url", "path", "target_url")
    method = str(raw.get("method") or "GET").upper()
    vuln_type = (
        str(raw.get("vuln_type") or raw.get("type") or raw.get("category") or "").strip().lower()
    )
    if not vuln_type:
        vuln_type = infer_vuln_type(title, raw)
    parameter = _first_present(raw, "parameter", "param", "field")
    auth_state = _first_present(raw, "auth_state", "authentication", "auth")
    role = _first_present(raw, "role", "user_role")
    workflow_step = _first_present(raw, "workflow_step", "step")
    severity = _first_present(raw, "severity", "risk")
    confidence = _float_or_none(raw.get("confidence"))
    raw_json = json.dumps(raw, ensure_ascii=False, default=str)
    fingerprint = str(raw.get("fingerprint") or "") or fingerprint_candidate(
        domain=domain_clean,
        vuln_type=vuln_type,
        title=title,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        auth_state=auth_state,
        role=role,
    )
    rejection_reason = deterministic_rejection_reason(raw, title=title)
    now = datetime.now(UTC).isoformat()
    lifecycle = "rejected" if rejection_reason else "needs_review"

    return FindingCandidate(
        id=str(raw.get("id") or f"cand-{uuid.uuid4().hex[:12]}"),
        domain=domain_clean,
        scan_id=scan_id,
        source_tool=source_tool,
        source_type=source_type,
        title=title,
        vuln_type=vuln_type,
        severity=severity,
        confidence=confidence,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        auth_state=auth_state,
        role=role,
        workflow_step=workflow_step,
        fingerprint=fingerprint,
        lifecycle_status=lifecycle,  # type: ignore[arg-type]
        rejection_reason=rejection_reason,
        raw_finding_json=raw_json,
        created_at=now,
        updated_at=now,
        last_seen_at=now,
    )


def infer_vuln_type(title: str, raw: dict[str, Any]) -> str:
    text = " ".join(
        str(raw.get(key) or "")
        for key in (
            "title",
            "finding_title",
            "description",
            "technical_analysis",
            "impact",
            "poc_description",
        )
    )
    text = f"{title} {text}".lower()
    for pattern, vuln_type in _VULN_TYPE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return vuln_type
    return "unknown"


def deterministic_rejection_reason(raw: dict[str, Any], *, title: str | None = None) -> str | None:
    text = " ".join(
        str(raw.get(key) or "")
        for key in (
            "title",
            "finding_title",
            "description",
            "technical_analysis",
            "impact",
            "poc_description",
            "evidence",
        )
    )
    if title:
        text = f"{title} {text}"
    has_impact = bool(
        re.search(
            r"unauthorized|accessed|extracted|modified|deleted|token|credential|pii|admin|account takeover|internal reachability|callback|readable protected",
            text,
            re.IGNORECASE,
        )
    )
    if has_impact:
        return None
    for pattern, reason in _REJECT_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            return reason
    return None


def _first_present(raw: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = raw.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _float_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _domain_from_url(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"https://{text}")
    host = parsed.netloc or parsed.path.split("/")[0]
    if host.startswith("www."):
        host = host[4:]
    return host.split(":")[0]
