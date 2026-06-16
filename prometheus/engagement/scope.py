"""Scope guardrail — 4-pattern allowlist + deny-wins + default-deny + suffix-confusion guard.

Ported from CBH ``engine/scope.py`` (200 lines of stdlib).

Semantics
---------

- **Patterns** (entries in ``in_scope``):
    1. Bare domain: ``example.com`` — matches ``example.com`` and any
       ``*.example.com`` (but NOT ``notexample.com``).
    2. Wildcard subdomain: ``*.example.com`` — matches any subdomain of
       ``example.com`` (and the apex, per convention).
    3. Exact: any other hostname literal (no ``*``, no path) is matched
       exactly.
    4. CIDR: an ``a.b.c.d/n`` entry is matched against the resolved
       client IP for a URL host.
- **Regex**: any pattern starting with ``re:`` is a regex anchored at
  the full host string.
- **Deny-wins**: an out-of-scope match always beats an in-scope match.
- **Default-deny**: a host with no positive in-scope match is rejected.
- **Suffix-confusion guard**: ``notexample.com`` does NOT match
  ``example.com`` (apex boundary check).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover - optional dep
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class Scope:
    """In-scope and out-of-scope host patterns.

    Loaded from a ``scope.yaml`` (a list of strings) or constructed
    directly from a list of hosts/patterns.
    """

    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        if yaml is None:
            raise RuntimeError("PyYAML not available; cannot load scope.yaml")
        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError(f"scope.yaml {path} must parse to a dict")
        in_scope = list(data.get("in_scope") or [])
        out_of_scope = list(data.get("out_of_scope") or [])
        return cls(in_scope=in_scope, out_of_scope=out_of_scope)

    @classmethod
    def for_domain(cls, domain: str) -> "Scope":
        return cls(
            in_scope=[domain, f"*.{domain}"],
            out_of_scope=[
                "localhost",
                "127.0.0.1",
                "::1",
                "169.254.0.0/16",  # link-local
                "metadata.google.internal",
                "169.254.169.254",  # cloud metadata
            ],
        )

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------
    def in_scope_host(self, host: str) -> bool:
        """Return True iff ``host`` is in scope (and not in out-of-scope)."""
        if not host:
            return False
        host = host.strip().lower().rstrip(".")
        if not host:
            return False

        # Out-of-scope always wins.
        for pattern in self.out_of_scope:
            if self._match(pattern, host):
                logger.debug("host %r denied by out-of-scope pattern %r", host, pattern)
                return False

        # Must positively match an in-scope pattern.
        for pattern in self.in_scope:
            if self._match(pattern, host):
                return True
        return False

    def in_scope_url(self, url: str) -> bool:
        """Return True iff the URL's host is in scope."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = parsed.hostname or ""
        return self.in_scope_host(host)

    # ------------------------------------------------------------------
    # Pattern dispatch
    # ------------------------------------------------------------------
    def _match(self, pattern: str, host: str) -> bool:
        pattern = pattern.strip()
        if not pattern:
            return False

        # Regex form: re:<regex>
        if pattern.lower().startswith("re:"):
            try:
                return bool(re.match(pattern[3:].strip(), host, re.IGNORECASE))
            except re.error:
                return False

        # CIDR form: a.b.c.d/n
        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                return False
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                # Try DNS resolution.
                try:
                    infos = socket.getaddrinfo(host, None)
                except socket.gaierror:
                    return False
                for info in infos:
                    if not info or not info[4]:
                        continue
                    sockaddr = info[4]
                    if not sockaddr:
                        continue
                    ip_str = sockaddr[0]
                    try:
                        if self._ip_in_net(socket.inet_pton(socket.AF_INET, ip_str), net):
                            return True
                        if self._ip_in_net(socket.inet_pton(socket.AF_INET6, ip_str), net):
                            return True
                    except OSError:
                        continue
                return False
            return addr in net

        # Wildcard subdomain: *.example.com
        if pattern.startswith("*."):
            apex = pattern[2:].lower().rstrip(".")
            if not apex:
                return False
            # host must equal apex OR be <anything>.apex
            if host == apex:
                return True
            return host.endswith("." + apex)

        # Bare domain: example.com — matches apex AND any subdomain, but
        # NOT suffix confusion (notexample.com).
        if self._looks_like_bare_domain(pattern):
            apex = pattern.lower().rstrip(".")
            if host == apex:
                return True
            return host.endswith("." + apex)

        # Exact match fallback (case-insensitive).
        return host == pattern.lower().rstrip(".")

    def _looks_like_bare_domain(self, pattern: str) -> bool:
        """True if ``pattern`` is a domain literal (no scheme/path/wildcard)."""
        p = pattern.strip().lower()
        if not p or "*" in p or "/" in p or ":" in p or " " in p:
            return False
        return "." in p

    @staticmethod
    def _ip_in_net(packed: bytes, net: "ipaddress.IPv4Network | ipaddress.IPv6Network") -> bool:  # type: ignore[name-defined]
        try:
            return ipaddress.ip_address(packed) in net
        except ValueError:
            return False


__all__ = ["Scope"]
