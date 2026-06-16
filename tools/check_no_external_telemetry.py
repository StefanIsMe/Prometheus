#!/usr/bin/env python3
"""Guard against external-telemetry regression in Prometheus.

Fails (exit 1) if the Prometheus codebase contains:
  - any string constant referencing a known analytics / error-tracking /
    attribution domain
  - any import of a known telemetry / error-tracking SDK

Docstrings and comments are not checked. The guard's own source file is
not checked (it has to list the forbidden patterns somewhere).

Scope of the policy: per project rule, Prometheus never makes a
telemetry call to an external service. Threat-intel feeds (NVD, CISA,
OSV, etc.) are NOT telemetry and are not in scope of this check.

Run from the repo root:

    python tools/check_no_external_telemetry.py

Exit codes:
  0  clean
  1  one or more violations found
  2  invocation error

Update the constants below to extend the policy rather than disabling
the check.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SELF_NAME = "check_no_external_telemetry.py"

# Domains Prometheus must NEVER call. Hard fail on match in any string
# constant in the codebase.
FORBIDDEN_DOMAINS: tuple[str, ...] = (
    "posthog.com",
    "scarf.sh",
    "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "sentry.io",
    "bugsnag.com",
    "datadoghq.com",
    "newrelic.com",
    "fullstory.com",
    "hotjar.com",
    "intercom.io",
    "pendo.io",
    "optimizely.com",
    "hubspot.com",
    "google-analytics.com",
    "googletagmanager.com",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "mailchimp.com",
)

# Top-level Python module names that Prometheus must NEVER import.
FORBIDDEN_IMPORTS: tuple[str, ...] = (
    "posthog",
    "sentry_sdk",
    "mixpanel",
    "segment",
    "bugsnag",
    "datadog",
    "newrelic",
    "fullstory",
    "hotjar",
    "intercom",
    "pendo",
    "optimizely",
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {"__pycache__", ".git", "node_modules", ".venv", "venv", ".mypy_cache", ".ruff_cache"}
)


def iter_python_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*.py"):
        if any(part in SKIP_DIR_NAMES for part in p.parts):
            continue
        out.append(p)
    return out


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map each AST node to its parent (for docstring detection)."""
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _is_docstring(node: ast.AST, parent_map: dict[ast.AST, ast.AST]) -> bool:
    """True when `node` is a string Constant serving as a docstring.

    A docstring appears in the AST as ``ast.Expr(value=Constant(str))`` as
    the first statement of a Module, FunctionDef, AsyncFunctionDef, or
    ClassDef body.
    """
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    parent = parent_map.get(node)
    if not isinstance(parent, ast.Expr) or parent.value is not node:
        return False
    grandparent = parent_map.get(parent)
    if isinstance(grandparent, ast.Module):
        return bool(grandparent.body) and grandparent.body[0] is parent
    if isinstance(grandparent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return bool(grandparent.body) and grandparent.body[0] is parent
    return False


def check_file(path: Path) -> list[str]:
    if path.name == SELF_NAME:
        return []
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    try:
        tree = ast.parse(content, filename=str(path))
    except SyntaxError:
        return [f"{path}: SyntaxError — fix before the guard can scan this file"]

    parent_map = _build_parent_map(tree)
    errors: list[str] = []

    for node in ast.walk(tree):
        # Forbidden string constant (skip docstrings)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _is_docstring(node, parent_map):
                continue
            for domain in FORBIDDEN_DOMAINS:
                if domain in node.value:
                    errors.append(
                        f"{path}:{node.lineno}: forbidden analytics domain "
                        f"'{domain}' in string literal"
                    )
                    break

        # `import x` / `import x.y`
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in FORBIDDEN_IMPORTS:
                    errors.append(
                        f"{path}:{node.lineno}: forbidden telemetry import '{top}'"
                    )

        # `from x import y` / `from x.y import z`
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in FORBIDDEN_IMPORTS:
                errors.append(
                    f"{path}:{node.lineno}: forbidden telemetry import '{top}'"
                )

    return errors


def main() -> int:
    repo = REPO_ROOT
    if not (repo / "prometheus").is_dir():
        print(f"error: {repo / 'prometheus'} not found; run from repo root", file=sys.stderr)
        return 2

    files = iter_python_files(repo)
    all_errors: list[str] = []
    for f in files:
        all_errors.extend(check_file(f))

    if all_errors:
        print("Telemetry guard FAILED:")
        print()
        for e in all_errors:
            print(f"  {e}")
        print()
        print(
            f"Found {len(all_errors)} violation(s) across {len(files)} file(s). "
            f"See {Path(__file__).name} for the policy."
        )
        return 1
    print(f"Telemetry guard OK: {len(files)} file(s) scanned, no violations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
