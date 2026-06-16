"""Conditionally-Valid matrix — ported from CBH triage-validation skill.

A finding that triggers a chain (e.g., open redirect + OAuth) is valid;
without the chain it is rejected by :mod:`prometheus.core.always_rejected`.
The chain linker (Change 3.2) consumes this module to find chain
candidates across an engagement.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)


_DATA_FILE = Path(__file__).resolve().parent.parent / "skills" / "data" / "conditionally_valid.json"


@dataclass(frozen=True)
class Chain:
    id: str
    title: str
    primary: str
    links_required: tuple[str, ...]
    severity_when_chained: str
    description: str


@lru_cache(maxsize=1)
def _load_chains() -> tuple[Chain, ...]:
    if not _DATA_FILE.exists():
        logger.warning("conditionally_valid.json missing at %s", _DATA_FILE)
        return tuple()
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("conditionally_valid.json unreadable: %s", exc)
        return tuple()
    chains: list[Chain] = []
    for entry in raw.get("chains", []):
        if not isinstance(entry, dict):
            continue
        cid = str(entry.get("id", "")).strip()
        if not cid:
            continue
        chains.append(
            Chain(
                id=cid,
                title=str(entry.get("title", cid)),
                primary=str(entry.get("primary", "")).lower(),
                links_required=tuple(str(x).lower() for x in entry.get("links_required", [])),
                severity_when_chained=str(entry.get("severity_when_chained", "P3")),
                description=str(entry.get("description", "")),
            )
        )
    return tuple(chains)


def list_chains() -> tuple[Chain, ...]:
    return _load_chains()


def _finding_text(finding: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "title",
        "summary",
        "description",
        "vuln_type",
        "endpoint",
        "chain_context",
        "chain",
        "tags",
        "evidence",
    ):
        v = finding.get(key)
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            parts.extend(str(x) for x in v)
        elif isinstance(v, dict):
            parts.append(json.dumps(v, sort_keys=True))
    return " ".join(parts).lower()


# Map short link tokens to the search phrases a finding must mention for
# the chain to count as closed. Keeps the data file declarative.
_LINK_PHRASES: dict[str, tuple[str, ...]] = {
    "open_redirect": ("open redirect",),
    "oauth_redirect_uri": (
        "oauth",
        "redirect_uri",
        "redirect-uri",
        "redirect uri",
        "authorization code",
    ),
    "ssrf": ("ssrf", "server-side request forgery", "server side request"),
    "imds_reachable": ("169.254.169.254", "imds", "metadata", "metadata service"),
    "internal_admin_reachable": (
        "internal admin",
        "localhost",
        "127.0.0.1",
        "internal grafana",
        "internal kibana",
        "internal admin panel",
    ),
    "cors_origin_reflect": (
        "cors",
        "access-control-allow-origin",
        "origin reflect",
        "reflects origin",
    ),
    "state_changing_endpoint": (
        "state-changing",
        "state changing",
        "post",
        "put",
        "delete",
        "patch",
        "/api/",
        "/v1/",
        "/v2/",
        "mutation",
    ),
    "idor": ("idor", "insecure direct object", "object reference"),
    "sensitive_data_in_response": (
        "ssn",
        "email",
        "phone",
        "address",
        "ssn",
        "credit card",
        "pan",
        "balance",
        "private key",
        "secret",
        "token",
        "password",
    ),
    "xss": ("xss", "cross-site scripting", "cross site scripting"),
    "stored_xss": ("stored xss", "persistent xss", "second-order xss", "stored cross-site"),
    "admin_viewer": (
        "admin viewer",
        "admin views",
        "admin sees",
        "admin will view",
        "admin panel",
        "admin dashboard",
        "admin reads",
    ),
    "csrf_protection_missing": (
        "no csrf",
        "missing csrf",
        "csrf token",
        "csrf protection",
    ),
    "auth_bypass": (
        "auth bypass",
        "authentication bypass",
        "authn bypass",
        "bypass auth",
    ),
    "admin_endpoint": (
        "/admin",
        "admin endpoint",
        "admin api",
        "admin route",
        "/internal/admin",
    ),
    "race_condition": ("race condition", "tocttou", "time-of-check", "concurrent request"),
    "balance_or_voucher_endpoint": (
        "withdraw",
        "transfer",
        "redeem",
        "voucher",
        "balance",
        "gift card",
        "credit",
        "payment",
    ),
    "account_enumeration": (
        "account enumeration",
        "user enumeration",
        "enumeration",
        "username enumeration",
        "email enumeration",
    ),
    "password_reset_flow": (
        "password reset",
        "/forgot",
        "forgot-password",
        "reset token",
        "reset link",
        "reset email",
    ),
    "info_disclosure": (
        "info disclosure",
        "information disclosure",
        "info leak",
        "sensitive header",
        "internal field",
    ),
    "downstream_vuln_or_chain": (
        "sqli",
        "sql injection",
        "path traversal",
        "ssrf",
        "rce",
        "command injection",
    ),
    "missing_rate_limit": (
        "missing rate limit",
        "no rate limit",
        "rate-limit missing",
        "rate limit missing",
    ),
    "no_captcha_or_lockout": (
        "no captcha",
        "no lockout",
        "no throttling",
        "no account lockout",
        "captcha missing",
    ),
}


def _has_link(finding: dict[str, Any], link: str) -> bool:
    """True if the finding's text indicates the given link is present.

    Looks up the link in :data:`_LINK_PHRASES` and returns True on any
    phrase match. Falls back to a literal substring search if the link
    has no entry, so custom chain templates still work.
    """
    text = _finding_text(finding)
    if not text:
        return False
    phrases = _LINK_PHRASES.get(link.lower())
    if phrases:
        return any(p in text for p in phrases)
    return link.lower() in text


def _primary_in_text(primary: str, text: str) -> bool:
    """True when the chain's primary vuln class appears in the text.

    The chain data uses snake_case tokens (e.g. ``open_redirect``) which
    won't appear verbatim in finding text (``"open redirect"`` is the
    natural phrasing). Look up the token in :data:`_LINK_PHRASES` and
    accept any phrase; fall back to a literal substring match.
    """
    if not primary:
        return True
    phrases = _LINK_PHRASES.get(primary.lower())
    if phrases:
        return any(p in text for p in phrases)
    return primary.lower() in text


def conditionally_valid(finding: dict[str, Any]) -> Chain | None:
    """Return the chain this finding is part of, or None.

    A finding matches a chain when its primary vuln class matches the
    chain's ``primary`` field AND the finding's text indicates ALL
    ``links_required`` are present. Returns the first matching chain.
    """
    text = _finding_text(finding)
    if not text:
        return None
    for chain in _load_chains():
        if not _primary_in_text(chain.primary, text):
            continue
        if all(_has_link(finding, link) for link in chain.links_required):
            return chain
    return None


def find_chain_links(findings: Iterable[dict[str, Any]]) -> list[Chain]:
    """Find every chain that 2+ findings in the engagement could close.

    Returns the set of chains whose ``links_required`` are covered by the
    union of finding texts. The actual chain-link report is the
    responsibility of :mod:`prometheus.core.chain_linker` (Change 3.2).
    """
    findings = list(findings)
    closed: list[Chain] = []
    for chain in _load_chains():
        present: set[str] = set()
        for f in findings:
            for link in chain.links_required:
                if _has_link(f, link):
                    present.add(link)
        if len(present & set(chain.links_required)) >= len(chain.links_required) - 1:
            # Allow 1 missing link (the chain linker fills it).
            closed.append(chain)
    return closed


__all__ = ["Chain", "conditionally_valid", "find_chain_links", "list_chains"]
