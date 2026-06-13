"""Tests for the orphan-prune pass in scripts/prom_rl_loop.py.

Background: the audit found 50 run.json files with ``status=running``
and no ``end_time`` that are 1-2 weeks old. The existing
``_mark_stuck_runs`` in prom_rl_loop.py handles this — Phase 4B
extends the heartbeat to cover the case where the run.json has
``status=None`` (orphaned before status was ever set).

This file:

  1. Unit-tests that a stale run.json (status=running, no end_time,
     2 days old) is marked stuck with end_time set.
  2. Unit-tests that a recent run.json (status=running, 30 s old)
     is NOT touched.
  3. Unit-tests that a run.json with status=completed is NOT touched
     even if it is old.
  4. Unit-tests that a run.json with status=None (orphan) and old
     timestamp IS marked stuck.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT))

import scripts.prom_rl_loop as rl  # noqa: E402


def _write_run_json(run_dir: Path, *, status: str | None, age_seconds: int) -> None:
    """Write a run.json with the given status and backdate its mtime."""
    run_dir.mkdir(parents=True, exist_ok=True)
    run_json = run_dir / "run.json"
    data: dict = {"target": "example.com", "scan_id": run_dir.name}
    if status is not None:
        data["status"] = status
    run_json.write_text(json.dumps(data))
    # Backdate the file's mtime so the heartbeat considers it stale.
    old_time = time.time() - age_seconds
    import os
    os.utime(run_json, (old_time, old_time))


def _setup_prom_runs(monkeypatch, tmp_path: Path) -> None:
    """Point PROM_RUNS_CANDIDATES at a temp dir so the prune pass
    only sees the test fixtures."""
    (tmp_path / "prometheus_runs").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(rl, "PROM_RUNS_CANDIDATES", [tmp_path / "prometheus_runs"])


# ---------------------------------------------------------------------------
# 1. Stale running run.json is marked stuck
# ---------------------------------------------------------------------------

def test_stale_running_run_is_marked_stuck(monkeypatch, tmp_path: Path) -> None:
    """A 2-day-old running run.json with no end_time must be marked stuck."""
    _setup_prom_runs(monkeypatch, tmp_path)
    run_dir = tmp_path / "prometheus_runs" / "scan-stale"
    _write_run_json(run_dir, status="running", age_seconds=2 * 86400)

    patched = rl._mark_stuck_runs()
    assert patched == 1

    data = json.loads((run_dir / "run.json").read_text())
    assert data["status"] == "stuck"
    assert "end_time" in data
    assert "stuck_reason" in data


# ---------------------------------------------------------------------------
# 2. Recent running run.json is NOT touched
# ---------------------------------------------------------------------------

def test_recent_running_run_is_not_touched(monkeypatch, tmp_path: Path) -> None:
    """A 30-second-old run.json must not be marked stuck (within heartbeat)."""
    _setup_prom_runs(monkeypatch, tmp_path)
    run_dir = tmp_path / "prometheus_runs" / "scan-fresh"
    _write_run_json(run_dir, status="running", age_seconds=30)

    patched = rl._mark_stuck_runs()
    assert patched == 0

    data = json.loads((run_dir / "run.json").read_text())
    assert data["status"] == "running"
    assert "end_time" not in data


# ---------------------------------------------------------------------------
# 3. Completed run.json is not touched even if old
# ---------------------------------------------------------------------------

def test_completed_run_is_not_touched(monkeypatch, tmp_path: Path) -> None:
    """A 2-day-old completed run.json is left alone."""
    _setup_prom_runs(monkeypatch, tmp_path)
    run_dir = tmp_path / "prometheus_runs" / "scan-done"
    _write_run_json(run_dir, status="completed", age_seconds=2 * 86400)

    patched = rl._mark_stuck_runs()
    assert patched == 0

    data = json.loads((run_dir / "run.json").read_text())
    assert data["status"] == "completed"


# ---------------------------------------------------------------------------
# 4. Orphan run.json (status=None) is marked stuck
# ---------------------------------------------------------------------------

def test_orphan_status_none_is_marked_stuck(monkeypatch, tmp_path: Path) -> None:
    """A run.json with no status key (orphaned) and old timestamp is marked stuck."""
    _setup_prom_runs(monkeypatch, tmp_path)
    run_dir = tmp_path / "prometheus_runs" / "scan-orphan"
    _write_run_json(run_dir, status=None, age_seconds=2 * 86400)

    patched = rl._mark_stuck_runs()
    assert patched == 1

    data = json.loads((run_dir / "run.json").read_text())
    assert data["status"] == "stuck"
    assert "end_time" in data
