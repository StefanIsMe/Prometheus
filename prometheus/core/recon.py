"""SPA-aware recon — deterministic pre-step for stage4.

Ported from CBH ``engine/recon.py``. Fetches a seed URL, downloads
same-origin JS bundles, regex-mines API routes, scans for secrets,
classifies endpoints. Output: ``arsenal.md`` consumed by the deep-dive
agent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


_JS_BUNDLE_PATTERNS = (
    re.compile(r"src=[\"']([^\"']+\.js)[\"']", re.IGNORECASE),
    re.compile(r"import\(['\"]([^'\"]+\.js)['\"]\)", re.IGNORECASE),
    re.compile(r"import\s+['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"require\(['\"]([^'\"]+)['\"]\)", re.IGNORECASE),
    re.compile(r"new\s+URL\(['\"]([^'\"]+)['\"]", re.IGNORECASE),
)

_API_PATH_PATTERNS = (
    re.compile(r"['\"](/api/[A-Za-z0-9_\-./{}:?&=]+)['\"]"),
    re.compile(r"['\"](/v[0-9]+/[A-Za-z0-9_\-./{}:?&=]+)['\"]"),
    re.compile(r"['\"](/graphql[^'\"]*)['\"]"),
    re.compile(r"['\"](/rest/[A-Za-z0-9_\-./{}:?&=]+)['\"]"),
    re.compile(r"['\"](/oauth[^\"']*)['\"]"),
    re.compile(r"['\"](/auth[^\"']*)['\"]"),
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "aws_secret_access_key",
        re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]+([A-Za-z0-9/+]{40})"),
    ),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("slack_token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("stripe_key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}")),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "internal_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
    (
        "internal_hostname",
        re.compile(
            r"\b(?:[a-z0-9-]+\.)*(?:internal|corp|local|lan|intranet|staging|dev|qa|preprod)\.[a-z.]{2,}\b",
            re.IGNORECASE,
        ),
    ),
)

_MAX_BUNDLE_BYTES = 2 * 1024 * 1024  # 2MB cap per JS bundle
_MAX_HTML_BYTES = 5 * 1024 * 1024
_USER_AGENT = "prometheus-recon/1.0 (engagement recon)"


@dataclass
class ReconEndpoint:
    url: str
    method: str = "GET"
    classification: str = "unknown"  # public | authenticated | sensitive | admin | unknown
    source: str = ""  # js-bundle | sitemaps | openapi | heuristic
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "classification": self.classification,
            "source": self.source,
            "notes": list(self.notes),
        }


@dataclass
class ReconSecret:
    kind: str
    value: str
    location: str  # where it was found
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "location": self.location,
            "notes": list(self.notes),
        }


@dataclass
class ReconResult:
    seed_url: str
    started_at: str
    finished_at: str | None = None
    js_bundles: list[str] = field(default_factory=list)
    endpoints: list[ReconEndpoint] = field(default_factory=list)
    secrets: list[ReconSecret] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed_url": self.seed_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "js_bundles": list(self.js_bundles),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "secrets": [s.to_dict() for s in self.secrets],
            "errors": list(self.errors),
            "notes": list(self.notes),
        }


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _same_origin(seed: str, candidate: str) -> bool:
    try:
        a = urlparse(seed)
        b = urlparse(candidate)
    except ValueError:
        return False
    if not a.netloc or not b.netloc:
        return False
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _classify_endpoint(url: str) -> str:
    """Heuristic endpoint classifier. Order matters — most specific first."""
    u = url.lower()
    if any(tok in u for tok in ("/admin", "/internal/", "/_admin", "/manage/")):
        return "admin"
    if any(
        tok in u
        for tok in ("/login", "/signup", "/register", "/session", "/token", "/oauth", "/auth")
    ):
        return "authenticated"
    # API-shape paths are authenticated by default; user-scoped paths escalate.
    if any(tok in u for tok in ("/me", "/user", "/account", "/profile", "/users/{")):
        return "sensitive"
    if any(tok in u for tok in ("/api/", "/v1/", "/v2/", "/rest/", "/graphql")):
        return "authenticated"
    return "public"


def _scan_text_for_secrets(text: str, location: str) -> list[ReconSecret]:
    out: list[ReconSecret] = []
    if not text:
        return out
    for kind, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0)
            if len(value) > 256:  # truncate long matches
                value = value[:256] + "…"
            out.append(ReconSecret(kind=kind, value=value, location=location))
    return out


# ----------------------------------------------------------------------
# Sync recon
# ----------------------------------------------------------------------
def recon_seed(seed_url: str, *, max_bundles: int = 25) -> ReconResult:
    """Synchronous recon of a seed URL. Stdlib + httpx only."""
    result = ReconResult(
        seed_url=seed_url,
        started_at=datetime.now(UTC).isoformat(),
    )

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=20.0,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            # 1. Fetch seed HTML.
            try:
                r = client.get(seed_url)
            except httpx.HTTPError as exc:
                result.errors.append(f"seed fetch failed: {exc}")
                result.finished_at = datetime.now(UTC).isoformat()
                return result
            if r.status_code >= 400:
                result.errors.append(f"seed HTTP {r.status_code}")
                result.finished_at = datetime.now(UTC).isoformat()
                return result
            html = r.text[:_MAX_HTML_BYTES]

            # 2. Mine JS bundle URLs.
            bundle_urls: list[str] = []
            for pat in _JS_BUNDLE_PATTERNS:
                for m in pat.finditer(html):
                    candidate = urljoin(seed_url, m.group(1))
                    if _same_origin(seed_url, candidate) and candidate not in bundle_urls:
                        bundle_urls.append(candidate)
            bundle_urls = bundle_urls[:max_bundles]
            result.js_bundles = list(bundle_urls)

            # 3. Download + scan each bundle for endpoints + secrets.
            for bundle in bundle_urls:
                try:
                    rb = client.get(bundle)
                except httpx.HTTPError as exc:
                    result.errors.append(f"bundle fetch failed {bundle}: {exc}")
                    continue
                if rb.status_code >= 400:
                    continue
                body = rb.text[:_MAX_BUNDLE_BYTES]
                # Endpoints
                for pat in _API_PATH_PATTERNS:
                    for m in pat.finditer(body):
                        path = m.group(1)
                        endpoint_url = urljoin(seed_url, path)
                        if not _same_origin(seed_url, endpoint_url):
                            # external endpoint still noted if API-style
                            if not any(t in path for t in ("/api", "/v1", "/v2", "/graphql")):
                                continue
                        result.endpoints.append(
                            ReconEndpoint(
                                url=endpoint_url,
                                method="GET",
                                classification=_classify_endpoint(endpoint_url),
                                source="js-bundle",
                                notes=[f"mined from {bundle}"],
                            )
                        )
                # Secrets
                for s in _scan_text_for_secrets(body, f"js:{bundle}"):
                    result.secrets.append(s)
    except Exception as exc:  # pragma: no cover - defensive
        result.errors.append(f"recon crashed: {exc!r}")

    # De-dupe endpoints by (method, url).
    seen: set[tuple[str, str]] = set()
    deduped: list[ReconEndpoint] = []
    for ep in result.endpoints:
        key = (ep.method, ep.url)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ep)
    result.endpoints = deduped

    result.finished_at = datetime.now(UTC).isoformat()
    return result


# ----------------------------------------------------------------------
# Arsenal markdown renderer
# ----------------------------------------------------------------------
def render_arsenal_markdown(result: ReconResult) -> str:
    """Render the recon result as ``arsenal.md`` for the deep-dive agent."""
    lines: list[str] = [
        f"# Arsenal — recon for {result.seed_url}",
        "",
        f"- Started: {result.started_at}",
        f"- Finished: {result.finished_at or '<running>'}",
        f"- JS bundles discovered: {len(result.js_bundles)}",
        f"- Endpoints discovered: {len(result.endpoints)}",
        f"- Secrets/leaks discovered: {len(result.secrets)}",
        f"- Errors: {len(result.errors)}",
        "",
        "## JS bundles",
        "",
    ]
    for b in result.js_bundles:
        lines.append(f"- `{b}`")
    lines.append("")
    lines.append("## Endpoints")
    lines.append("")
    by_class: dict[str, list[ReconEndpoint]] = {}
    for ep in result.endpoints:
        by_class.setdefault(ep.classification, []).append(ep)
    for cls in ("admin", "sensitive", "authenticated", "public", "unknown"):
        eps = by_class.get(cls) or []
        if not eps:
            continue
        lines.append(f"### {cls} ({len(eps)})")
        for ep in eps:
            lines.append(f"- `{ep.method} {ep.url}` — {ep.source}")
        lines.append("")
    lines.append("## Secrets / leaks")
    lines.append("")
    if not result.secrets:
        lines.append("_None._")
    else:
        for s in result.secrets:
            lines.append(f"- **{s.kind}** at `{s.location}`: `{s.value}`")
    lines.append("")
    if result.errors:
        lines.append("## Errors")
        lines.append("")
        for e in result.errors:
            lines.append(f"- {e}")
        lines.append("")
    return "\n".join(lines)


def write_arsenal(result: ReconResult, dest: Path) -> Path:
    """Write the arsenal markdown + a JSON sidecar to ``dest``."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_arsenal_markdown(result), encoding="utf-8")
    sidecar = dest.with_suffix(".json")
    sidecar.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return dest


__all__ = [
    "ReconEndpoint",
    "ReconResult",
    "ReconSecret",
    "recon_seed",
    "render_arsenal_markdown",
    "write_arsenal",
]
