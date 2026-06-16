"""OpenAPI-aware auth enforcement sweep.

Given an OpenAPI / Swagger document, generate per-operation HTTP
probes that test whether the declared security requirements are
actually enforced. The output is a list of ``AuthProbe`` items the
deep-dive agent can replay.

A real run will hit the live API; this module produces the probe
list. Probe replay is the runner's responsibility.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx


@dataclass
class AuthProbe:
    operation_id: str
    method: str
    path: str
    declared_security: list[dict[str, Any]]
    probe_url: str
    expected_status_with_auth: int
    probe_kind: str  # "no_auth" | "wrong_token" | "expired_token"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "method": self.method,
            "path": self.path,
            "declared_security": list(self.declared_security),
            "probe_url": self.probe_url,
            "expected_status_with_auth": self.expected_status_with_auth,
            "probe_kind": self.probe_kind,
            "notes": list(self.notes),
        }


_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _resolve_path_params(path: str, params: list[dict[str, Any]] | None) -> str:
    """Substitute ``{x}`` placeholders with a sample integer / string."""
    if not params:
        return re.sub(r"\{[^}]+\}", "1", path)
    by_name = {p.get("name"): p for p in params if isinstance(p, dict) and p.get("name")}

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        spec = by_name.get(name) or {}
        schema = spec.get("schema") or {}
        stype = str(schema.get("type") or "string").lower()
        if stype in ("integer", "number"):
            return "1"
        return "test"

    return re.sub(r"\{([^}]+)\}", repl, path)


def _declared_security_for_op(op: dict[str, Any], doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the resolved ``security`` schemes referenced by an operation."""
    sec = op.get("security")
    if sec is None:
        sec = doc.get("security") or []
    schemes = (
        doc.get("components", {}).get("securitySchemes") or doc.get("securityDefinitions") or {}
    )
    out: list[dict[str, Any]] = []
    if not isinstance(sec, list):
        return out
    for entry in sec:
        if not isinstance(entry, dict):
            continue
        for name, scopes in entry.items():
            scheme = schemes.get(name) or {}
            out.append(
                {
                    "scheme_name": name,
                    "type": scheme.get("type"),
                    "in": scheme.get("in"),
                    "scopes": list(scopes) if isinstance(scopes, (list, dict)) else [],
                }
            )
    return out


def build_auth_probes(
    openapi_doc: dict[str, Any],
    *,
    base_url: str | None = None,
) -> list[AuthProbe]:
    """Walk every operation in the OpenAPI doc and return auth probes.

    Probes are *instructions* — the runner replays them. This function
    does not perform HTTP.
    """
    probes: list[AuthProbe] = []
    paths = openapi_doc.get("paths") or {}
    if not isinstance(paths, dict):
        return probes
    base = (base_url or str(openapi_doc.get("servers", [{}])[0].get("url") or "")).rstrip("/")
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            params = op.get("parameters") or []
            resolved_path = _resolve_path_params(path, params)
            declared = _declared_security_for_op(op, openapi_doc)
            if not declared:
                # No declared security — still note it, but do not probe
                # for "wrong token" since the spec says no auth is needed.
                continue
            responses = op.get("responses") or {}
            success_keys = ("200", "201", "202", "204")
            expected = 200
            for k in success_keys:
                if k in responses:
                    expected = int(k)
                    break
            full_url = urljoin(base + "/", resolved_path.lstrip("/")) if base else resolved_path
            for kind in ("no_auth", "wrong_token"):
                probes.append(
                    AuthProbe(
                        operation_id=str(op.get("operationId") or f"{method}:{path}"),
                        method=method.upper(),
                        path=resolved_path,
                        declared_security=declared,
                        probe_url=full_url,
                        expected_status_with_auth=expected,
                        probe_kind=kind,
                        notes=[
                            f"declared: {', '.join(s.get('scheme_name', '?') for s in declared)}"
                        ],
                    )
                )
    return probes


def write_auth_probes(probes: list[AuthProbe], dest) -> int:
    """Write probes to a JSON file. Returns the count written."""
    from pathlib import Path

    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "probe_count": len(probes),
        "probes": [p.to_dict() for p in probes],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return len(probes)


__all__ = ["AuthProbe", "build_auth_probes", "write_auth_probes"]
