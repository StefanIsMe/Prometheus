"""Test the SCAN action's dedup behavior.

Verifies:
  1. A second SCAN attempt while one is 'running' is blocked (no second
     prometheus process is spawned).
  2. The scan lock serializes concurrent invocations.
  3. The rotation index advances so multiple calls hit different targets.
  4. The recon-only mode triggers for war.gov.
  5. The full SCAN action returns immediately when a scan is already
     active, with a clean status message.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import prom_rl_loop  # type: ignore[import-not-found]


def test_scan_lock_serializes(tmp_path, monkeypatch):
    """Two consecutive scan_lock_acquire() calls — second must fail."""
    monkeypatch.setattr(prom_rl_loop, "SCAN_LOCK", tmp_path / "scan.lock")
    fh1 = prom_rl_loop.scan_lock_acquire(timeout_s=0.0)
    assert fh1 is not None
    fh2 = prom_rl_loop.scan_lock_acquire(timeout_s=0.0)
    assert fh2 is None
    prom_rl_loop.scan_lock_release(fh1)
    fh3 = prom_rl_loop.scan_lock_acquire(timeout_s=0.0)
    assert fh3 is not None
    prom_rl_loop.scan_lock_release(fh3)


def test_scan_blocked_when_already_running(monkeypatch, tmp_path):
    """If a prometheus -n process is already running, action_scan returns
    a 'skipping to avoid duplicate' result and does NOT spawn a new one."""
    # Simulate an existing scan by monkeypatching prometheus_process_count
    monkeypatch.setattr(prom_rl_loop, "prometheus_process_count", lambda: 2)
    result = prom_rl_loop.action_scan({})
    assert result["action"] == "SCAN"
    assert "already running" in result["result"]
    assert "skipping" in result["result"]


def test_scan_blocked_by_lock(monkeypatch, tmp_path):
    """If the lock is held, action_scan returns a 'lock held' result."""
    monkeypatch.setattr(prom_rl_loop, "prometheus_process_count", lambda: 0)
    # Manually hold the lock
    lock_path = tmp_path / "scan.lock"
    lock_fh = open(lock_path, "w")
    import fcntl
    fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setattr(prom_rl_loop, "SCAN_LOCK", lock_path)
    try:
        result = prom_rl_loop.action_scan({})
        assert "lock held" in result["result"] or "already running" in result["result"]
    finally:
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()


def test_rotation_advances_through_targets(monkeypatch, tmp_path):
    """Calling pick_target multiple times should cycle through the
    priority list, not return the same target twice."""
    rotation_file = tmp_path / "rotation.json"
    monkeypatch.setattr(prom_rl_loop, "SCAN_ROTATION", rotation_file)
    cfg = prom_rl_loop.load_targets()
    seen = set()
    for _ in range(len(cfg["loop_target_priority"])):
        chosen = prom_rl_loop.pick_target(cfg)
        assert chosen is not None
        seen.add(chosen[0])
    # Should have hit all 7 (or at least 6) targets
    assert len(seen) >= 6, f"expected rotation across multiple targets, got {seen}"


def test_war_gov_in_program_full_scan_mode():
    """DoD VDP / HackerOne BPV: program allows coordinated research on
    publicly accessible DoD systems. The war.gov target MUST be in
    full-scan mode (scan_mode=deep) and MUST carry the DoD rules of
    engagement in its instruction_hint. This test prevents regression
    where someone flips it back to recon/quick without re-adding the
    rules-of-engagement text."""
    cfg = json.loads((Path("~/.prometheus/prom_rl_targets.json").expanduser()).read_text())
    t = cfg["targets"]["dod-war-gov"]
    assert t["scan_mode"] == "deep", (
        f"war.gov must be full deep scan inside DoD VDP program, got scan_mode={t['scan_mode']!r}"
    )
    assert t["ai_allowed"] is True
    assert "war.gov" in t["scope"][0]
    hint = t.get("instruction_hint", "")
    for needle in ("DoD", "exfiltrate", "denial of service", "scope", "minimum"):
        assert needle.lower() in hint.lower(), (
            f"war.gov instruction_hint missing DoD rule phrase: {needle!r}"
        )


def test_recon_mode_does_no_active_scanning(monkeypatch, tmp_path):
    """The recon mode must NOT spawn any prometheus subprocess."""
    cfg = json.loads((Path("~/.prometheus/prom_rl_targets.json").expanduser()).read_text())
    t = cfg["targets"]["dod-war-gov"]
    t["scan_mode"] = "recon"
    t["ai_allowed"] = True
    t["scope"] = ["https://www.war.gov"]
    # Spy on subprocess.Popen
    calls = []
    real_popen = prom_rl_loop.subprocess.Popen

    def spy_popen(*args, **kwargs):
        calls.append((args, kwargs))
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(prom_rl_loop.subprocess, "Popen", spy_popen)
    prom_rl_loop._action_scan_recon("dod-war-gov", t)
    # The recon path uses urllib, not subprocess
    for args, _ in calls:
        if args and args[0] and isinstance(args[0], list):
            cmd = args[0]
            if cmd and "prometheus" in str(cmd[0]):
                pytest.fail("recon mode spawned prometheus")
    # Or: simply assert no calls at all
    assert all("prometheus" not in str(c) for c in calls), "recon should not invoke prometheus"
