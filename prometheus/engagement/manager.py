"""Engagement manager — scaffold + load + save per-target folders.

Engagement.create(domain) scaffolds a fresh ``~/.prometheus/engagements/<domain>/``
folder. Engagement.load(domain) rehydrates state. Engagement.save() atomic-writes
state.json.

Engagement-folder layout is documented in the package ``__init__``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prometheus.engagement.state import EngagementState, SurfaceSet

logger = logging.getLogger(__name__)


DEFAULT_ENGAGEMENTS_ROOT = Path.home() / ".prometheus" / "engagements"


class EngagementExistsError(RuntimeError):
    """Raised when ``Engagement.create`` would clobber an existing folder."""


class EngagementNotFoundError(RuntimeError):
    """Raised when ``Engagement.load`` cannot find a folder."""


_SAFE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$")


def _validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or not _SAFE_DOMAIN_RE.match(domain):
        raise ValueError(
            f"Invalid engagement name {domain!r}; use letters, digits, dots, "
            "underscores, dashes; max 254 chars; must start alphanumeric."
        )
    return domain.lower()


def _default_scope_yaml(domain: str) -> str:
    return (
        "# Engagement scope configuration\n"
        "# 4-pattern allowlist + regex via re: + deny-wins + default-deny\n"
        "in_scope:\n"
        f'  - "{domain}"\n'
        f'  - "*.{domain}"\n'
        "out_of_scope:\n"
        '  - "localhost"\n'
        '  - "127.0.0.1"\n'
        '  - "169.254.0.0/16"   # link-local\n'
    )


def _default_scope_md(domain: str) -> str:
    return (
        f"# Scope: {domain}\n\n"
        "## In scope\n"
        f"- `{domain}`\n"
        f"- `*.{domain}`\n\n"
        "## Out of scope\n"
        "- Production data\n"
        "- Other tenants\n"
        "- DoS / volumetric\n\n"
        "## Rules of engagement\n"
        "- No automated submission to bounty programs.\n"
        "- All findings go through human review.\n"
    )


def _default_engine_log() -> str:
    return (
        f"# engine.log — {datetime.now(UTC).isoformat()}\n# Append-only log of engagement events.\n"
    )


@contextlib.contextmanager
def _suppress_oserror():
    try:
        yield
    except OSError:
        pass


@dataclass
class Engagement:
    """A single engagement folder.

    Use :meth:`create` to scaffold a new one or :meth:`load` to rehydrate.
    """

    root: Path
    state: EngagementState

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------
    @classmethod
    def create(
        cls,
        domain: str,
        *,
        root: Path | None = None,
        scope_yaml: str | None = None,
        scope_md: str | None = None,
        overwrite: bool = False,
    ) -> "Engagement":
        name = _validate_domain(domain)
        eng_root = (root or DEFAULT_ENGAGEMENTS_ROOT) / name
        if eng_root.exists() and not overwrite:
            if (eng_root / "state.json").exists():
                raise EngagementExistsError(f"Engagement {name!r} already exists at {eng_root}")
        eng_root.mkdir(parents=True, exist_ok=True)
        (eng_root / "findings").mkdir(exist_ok=True)
        (eng_root / "evidence").mkdir(exist_ok=True)
        (eng_root / "runs").mkdir(exist_ok=True)
        (eng_root / "scope.yaml").write_text(
            scope_yaml or _default_scope_yaml(name), encoding="utf-8"
        )
        (eng_root / "scope.md").write_text(scope_md or _default_scope_md(name), encoding="utf-8")
        if not (eng_root / "engine.log").exists():
            (eng_root / "engine.log").write_text(_default_engine_log(), encoding="utf-8")
        state = EngagementState.new(name)
        eng = cls(root=eng_root, state=state)
        eng.save()
        logger.info("Engagement %s created at %s", name, eng_root)
        return eng

    @classmethod
    def load(cls, domain: str, *, root: Path | None = None) -> "Engagement":
        name = _validate_domain(domain)
        eng_root = (root or DEFAULT_ENGAGEMENTS_ROOT) / name
        if not eng_root.is_dir():
            raise EngagementNotFoundError(f"Engagement {name!r} not found at {eng_root}")
        state_path = eng_root / "state.json"
        if state_path.exists():
            try:
                state = EngagementState.from_json(state_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, ValueError) as exc:
                raise EngagementNotFoundError(
                    f"Engagement {name!r} state.json is corrupt: {exc}"
                ) from exc
        else:
            # Recover a fresh state if state.json is missing.
            state = EngagementState.new(name)
        return cls(root=eng_root, state=state)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------
    def evidence_path(self, fname: str) -> Path:
        """Return the path to a file in ``evidence/`` (does not create)."""
        return self.root / "evidence" / fname

    def finding_path(self, fname: str) -> Path:
        return self.root / "findings" / fname

    def run_dir(self, run_id: str) -> Path:
        d = self.root / "runs" / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def stage_path(self, run_id: str, stage_name: str) -> Path:
        d = self.run_dir(run_id) / "stages"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{stage_name}.json"

    def recon_path(self, run_id: str, fname: str = "arsenal.md") -> Path:
        d = self.run_dir(run_id) / "recon"
        d.mkdir(parents=True, exist_ok=True)
        return d / fname

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self) -> None:
        """Atomic-save ``state.json`` (write to .tmp + os.replace)."""
        state_path = self.root / "state.json"
        tmp_path = state_path.with_suffix(state_path.suffix + ".tmp")
        tmp_path.write_text(self.state.to_json(), encoding="utf-8")
        os.replace(tmp_path, state_path)
        with _suppress_oserror():
            state_path.chmod(0o600)

    def append_log(self, line: str) -> None:
        """Append a line to ``engine.log`` (best-effort)."""
        log_path = self.root / "engine.log"
        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"[{datetime.now(UTC).isoformat()}] {line}\n")
        except OSError as exc:
            logger.warning("Failed to append engine.log: %s", exc)

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------
    def record_candidate(self, candidate: dict[str, Any]) -> None:
        self.state.candidates.append(candidate)
        self.save()

    def record_confirmed(self, finding: dict[str, Any]) -> None:
        self.state.confirmed.append(finding)
        self.save()

    def set_threat_model(self, threat_model: dict[str, Any]) -> None:
        self.state.threat_model = threat_model
        self.state.phase = "recon"
        self.save()

    def update_surface(self, surface: SurfaceSet) -> None:
        self.state.surface = surface
        self.save()

    def add_target(self, target: str) -> None:
        if target and target not in self.state.targets:
            self.state.targets.append(target)
            self.save()

    def set_phase(self, phase: str) -> None:
        self.state.phase = phase
        self.save()
