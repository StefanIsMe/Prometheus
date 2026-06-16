"""Run manifest — config + prompt + model hashing per scan run.

Extends :mod:`prometheus.core.scan_persistence` with a
``run_manifest.json`` schema that captures the inputs and outputs of
each pipeline stage. The manifest makes scans reproducible: two runs
with the same config + prompts produce the same config_hash /
prompt_hash; two runs with different prompts produce different
prompt_hashes.

Schema (VVAH-derived):

    {
      "version": 1,
      "run_id": "...",
      "started_at": "...",
      "finished_at": "...",
      "config_hash": "sha256:...",
      "prompt_hash": "sha256:...",
      "model_ids": {"s4_deepdive": "claude-sonnet-4-6", ...},
      "stage_records": [
        {"stage": "s2_threatmodel", "started_at": "...", "finished_at": "...",
         "duration_s": 1.2, "model_id": "...", "input_hash": "...", "output_hash": "..."}
      ],
      "tool_versions": {"prometheus": "...", "python": "..."}
    }
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1


@dataclass
class StageRecord:
    stage: str
    started_at: str
    finished_at: str | None = None
    duration_s: float = 0.0
    model_id: str | None = None
    input_hash: str | None = None
    output_hash: str | None = None
    notes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunManifest:
    run_id: str
    started_at: str
    config_hash: str
    prompt_hash: str
    model_ids: dict[str, str] = field(default_factory=dict)
    stage_records: list[StageRecord] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    finished_at: str | None = None
    notes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "config_hash": self.config_hash,
            "prompt_hash": self.prompt_hash,
            "model_ids": dict(self.model_ids),
            "stage_records": [s.to_dict() for s in self.stage_records],
            "tool_versions": dict(self.tool_versions),
            "notes": dict(self.notes),
        }


# ----------------------------------------------------------------------
# Hash helpers
# ----------------------------------------------------------------------
def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def hash_config(config: Mapping[str, Any]) -> str:
    """Stable SHA-256 over the canonical JSON of a config mapping."""
    blob = _canonical_json(dict(config))
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def hash_prompts(prompts: Mapping[str, str] | Iterable[tuple[str, str]]) -> str:
    """Stable SHA-256 over the canonical JSON of a prompt mapping."""
    if not isinstance(prompts, Mapping):
        prompts = dict(prompts)
    blob = _canonical_json(dict(prompts))
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def hash_payload(payload: Any) -> str:
    """Stable SHA-256 over the canonical JSON of an arbitrary payload."""
    blob = _canonical_json(payload)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Tool versions
# ----------------------------------------------------------------------
def _python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def _prometheus_version() -> str:
    PackageNotFoundError: type[Exception] = Exception  # type: ignore[misc]  # codeql[py/uninitialized-local-variable] : ensure name is bound before the `except` clause below
    try:
        from importlib.metadata import version, PackageNotFoundError

        return version("prometheus")
    except (ImportError, PackageNotFoundError):
        return "unknown"


# ----------------------------------------------------------------------
# Manifest builder
# ----------------------------------------------------------------------
def make_manifest(
    run_id: str,
    *,
    config: Mapping[str, Any],
    prompts: Mapping[str, str] | Iterable[tuple[str, str]],
    model_ids: Mapping[str, str] | None = None,
) -> RunManifest:
    """Build a fresh :class:`RunManifest` with config + prompt hashes."""
    return RunManifest(
        run_id=run_id,
        started_at=_dt.datetime.now(_dt.UTC).isoformat(),
        config_hash=hash_config(config),
        prompt_hash=hash_prompts(prompts),
        model_ids=dict(model_ids or {}),
        tool_versions={"python": _python_version(), "prometheus": _prometheus_version()},
    )


def record_stage(
    manifest: RunManifest,
    stage: str,
    *,
    started_at: str,
    finished_at: str | None = None,
    duration_s: float = 0.0,
    model_id: str | None = None,
    input_payload: Any = None,
    output_payload: Any = None,
    notes: Mapping[str, Any] | None = None,
) -> StageRecord:
    """Append a :class:`StageRecord` to ``manifest`` and return it."""
    rec = StageRecord(
        stage=stage,
        started_at=started_at,
        finished_at=finished_at,
        duration_s=duration_s,
        model_id=model_id,
        input_hash=hash_payload(input_payload) if input_payload is not None else None,
        output_hash=hash_payload(output_payload) if output_payload is not None else None,
        notes=dict(notes or {}),
    )
    manifest.stage_records.append(rec)
    return rec


def finalize(manifest: RunManifest) -> RunManifest:
    """Set the manifest's ``finished_at`` timestamp."""
    manifest.finished_at = _dt.datetime.now(_dt.UTC).isoformat()
    return manifest


# ----------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------
def write_manifest(manifest: RunManifest, dest: str | Path) -> Path:
    """Write the manifest to ``dest`` as human-readable JSON."""
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest.to_dict()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    return path


def read_manifest(path: str | Path) -> dict[str, Any]:
    """Read a manifest back from disk as a dict (no validation)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


__all__ = [
    "RunManifest",
    "SCHEMA_VERSION",
    "StageRecord",
    "finalize",
    "hash_config",
    "hash_payload",
    "hash_prompts",
    "make_manifest",
    "read_manifest",
    "record_stage",
    "write_manifest",
]
