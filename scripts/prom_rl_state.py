#!/usr/bin/env python3
"""
Prometheus RL Loop — persistent state layer.

Manages the SQLite DB that backs the /loop-driven self-improvement controller
(see /home/stefan/.claude/plans/imperative-sleeping-bunny.md).

The DB lives at ~/.prometheus/prom_rl_state.db. Schema is created idempotently
on `init`. All other commands require the schema to exist.

Subcommands:
  init                      Create schema if missing, print DB path
  record-iter <action> <target> <summary>   Append an iteration row
  record-scan <scan_id> <target> <class> <verdict> <evidence>   Append a scans_reviewed row
  record-fix <iter_id> <file> <commit_sha> <reason> <expected>  Append a fixes_applied row
  record-test <iter_id> <file> <result> <before> <after>        Append a tests_added row
  record-score <iter_id> <scan_id> <score> <components_json>   Append a score_history row
  record-policy <arm> <score>   Update policies table (running reward)
  last-iterations [N]          Print last N iteration rows (default 20)
  best-arm                     Print action with highest running reward
  status                       Print a one-shot summary
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path.home() / ".prometheus" / "prom_rl_state.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS iterations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    summary TEXT
);

CREATE TABLE IF NOT EXISTS scans_reviewed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    target TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    candidate_class TEXT,
    verdict TEXT,
    evidence_path TEXT
);

CREATE TABLE IF NOT EXISTS fixes_applied (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iter_id INTEGER,
    file TEXT NOT NULL,
    commit_sha TEXT,
    reason TEXT,
    expected_improvement TEXT,
    applied_at TEXT NOT NULL,
    FOREIGN KEY (iter_id) REFERENCES iterations(id)
);

CREATE TABLE IF NOT EXISTS tests_added (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iter_id INTEGER,
    file TEXT NOT NULL,
    result TEXT,
    before_pass INTEGER,
    after_pass INTEGER,
    added_at TEXT NOT NULL,
    FOREIGN KEY (iter_id) REFERENCES iterations(id)
);

CREATE TABLE IF NOT EXISTS score_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iter_id INTEGER,
    scan_id TEXT,
    score REAL NOT NULL,
    components_json TEXT,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (iter_id) REFERENCES iterations(id)
);

CREATE TABLE IF NOT EXISTS policies (
    arm TEXT PRIMARY KEY,
    score REAL NOT NULL DEFAULT 0.0,
    uses INTEGER NOT NULL DEFAULT 0,
    last_used TEXT
);

-- Mirror of external_submissions (Bugcrowd/H1). Used by the RL layer
-- to detect when a target domain has fresh closures and to discourage
-- scans against those domains without a new chain of evidence.
CREATE TABLE IF NOT EXISTS external_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    external_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    triaged_at TEXT,
    ingested_at TEXT NOT NULL,
    UNIQUE(platform, external_id)
);

CREATE INDEX IF NOT EXISTS idx_iter_started ON iterations(started_at);
CREATE INDEX IF NOT EXISTS idx_scan_reviewed ON scans_reviewed(reviewed_at);
CREATE INDEX IF NOT EXISTS idx_score_recorded ON score_history(recorded_at);
CREATE INDEX IF NOT EXISTS idx_external_findings_domain ON external_findings(domain);
CREATE INDEX IF NOT EXISTS idx_external_findings_status ON external_findings(status);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init() -> int:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Seed the four action arms if missing
        for arm in ("SCAN", "REVIEW", "FIX", "TEST"):
            conn.execute(
                "INSERT OR IGNORE INTO policies(arm, score, uses) VALUES (?, 0.0, 0)",
                (arm,),
            )
        conn.commit()
    print(str(DB_PATH))
    return 0


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def cmd_record_iter(args: argparse.Namespace) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO iterations(started_at, action, target, summary) VALUES (?, ?, ?, ?)",
            (now_iso(), args.action, args.target, args.summary),
        )
        conn.commit()
        print(cur.lastrowid)
    return 0


def cmd_record_scan(args: argparse.Namespace) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans_reviewed(scan_id, target, reviewed_at, candidate_class, verdict, evidence_path) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                args.scan_id,
                args.target,
                now_iso(),
                args.candidate_class,
                args.verdict,
                args.evidence,
            ),
        )
        conn.commit()
        print(cur.lastrowid)
    return 0


def cmd_record_fix(args: argparse.Namespace) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO fixes_applied(iter_id, file, commit_sha, reason, expected_improvement, applied_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                args.iter_id,
                args.file,
                args.commit_sha,
                args.reason,
                args.expected,
                now_iso(),
            ),
        )
        conn.commit()
        print(cur.lastrowid)
    return 0


def cmd_record_test(args: argparse.Namespace) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO tests_added(iter_id, file, result, before_pass, after_pass, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                args.iter_id,
                args.file,
                args.result,
                int(args.before) if args.before is not None else None,
                int(args.after) if args.after is not None else None,
                now_iso(),
            ),
        )
        conn.commit()
        print(cur.lastrowid)
    return 0


def cmd_record_score(args: argparse.Namespace) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO score_history(iter_id, scan_id, score, components_json, recorded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                args.iter_id,
                args.scan_id,
                float(args.score),
                args.components or "{}",
                now_iso(),
            ),
        )
        conn.commit()
        print(cur.lastrowid)
    return 0


def cmd_record_policy(args: argparse.Namespace) -> int:
    with connect() as conn:
        conn.execute(
            "INSERT INTO policies(arm, score, uses, last_used) VALUES (?, ?, 1, ?) "
            "ON CONFLICT(arm) DO UPDATE SET score = score + excluded.score, uses = uses + 1, last_used = excluded.last_used",
            (args.arm, float(args.score), now_iso()),
        )
        conn.commit()
    return 0


def cmd_record_external(args: argparse.Namespace) -> int:
    """Mirror an external_submissions row into the RL state DB.

    The full truth lives in ~/.prometheus/prometheus.db; this is a
    lightweight mirror so the RL driver can read the closure count
    without touching the agent DB on every loop tick.
    """
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO external_findings
                (platform, external_id, domain, finding_hash, status, triaged_at, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(platform, external_id) DO UPDATE SET
                status = excluded.status,
                triaged_at = excluded.triaged_at,
                ingested_at = excluded.ingested_at
            """,
            (
                args.platform,
                args.external_id,
                args.domain,
                args.finding_hash,
                args.status,
                args.triaged_at,
                now_iso(),
            ),
        )
        conn.commit()
    return 0


def cmd_count_external_closed(args: argparse.Namespace) -> int:
    """Count distinct external_findings rows for *domain* closed
    (status in {not_reproducible, na, informative, rejected, duplicate})
    in the last *days* days. Mirrors the prometheus.db query.
    """
    cutoff_iso = (datetime.now(timezone.utc) - __import__("datetime").timedelta(days=args.days)).isoformat()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM external_findings
            WHERE domain = ? AND status IN
                ('not_reproducible', 'na', 'informative', 'rejected', 'duplicate')
              AND triaged_at >= ?
            """,
            (args.domain, cutoff_iso),
        ).fetchone()
    print(int(row["cnt"] or 0) if row else 0)
    return 0


def cmd_last_iterations(args: argparse.Namespace) -> int:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, started_at, action, target, summary FROM iterations ORDER BY id DESC LIMIT ?",
            (args.n,),
        ).fetchall()
        for r in rows:
            print(f"#{r['id']} {r['started_at']} {r['action']:7s} target={r['target'] or '-':24s} {r['summary'] or ''}")
    return 0


def cmd_best_arm(args: argparse.Namespace) -> int:
    """Return the action arm with the highest running average reward (greedy pick)."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT arm, score, uses FROM policies WHERE uses > 0 ORDER BY (score / uses) DESC, uses DESC"
        ).fetchall()
        if not rows:
            # Cold start: pick SCAN to seed observations
            print("SCAN")
            return 0
        for r in rows:
            avg = r["score"] / r["uses"] if r["uses"] else 0.0
            print(f"{r['arm']:7s} avg={avg:+.3f} uses={r['uses']} total={r['score']:+.2f}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    with connect() as conn:
        n_iter = conn.execute("SELECT COUNT(*) FROM iterations").fetchone()[0]
        n_scan = conn.execute("SELECT COUNT(*) FROM scans_reviewed").fetchone()[0]
        n_fix = conn.execute("SELECT COUNT(*) FROM fixes_applied").fetchone()[0]
        n_test = conn.execute("SELECT COUNT(*) FROM tests_added").fetchone()[0]
        n_score = conn.execute("SELECT COUNT(*) FROM score_history").fetchone()[0]
        n_ext = conn.execute("SELECT COUNT(*) FROM external_findings").fetchone()[0]
        last_score = conn.execute(
            "SELECT score, components_json, recorded_at FROM score_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
    print(f"DB: {DB_PATH}")
    print(f"iterations:      {n_iter}")
    print(f"scans_reviewed:  {n_scan}")
    print(f"fixes_applied:   {n_fix}")
    print(f"tests_added:     {n_test}")
    print(f"score_history:   {n_score}")
    print(f"external_findings: {n_ext}")
    if last_score:
        print(f"last_score:      {last_score['score']:+.3f}  at {last_score['recorded_at']}")
        try:
            comps = json.loads(last_score["components_json"])
            for k, v in comps.items():
                print(f"  - {k}: {v}")
        except (json.JSONDecodeError, TypeError):
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Prometheus RL state DB")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create schema if missing")

    pi = sub.add_parser("record-iter")
    pi.add_argument("action")
    pi.add_argument("target", nargs="?", default=None)
    pi.add_argument("summary", nargs="?", default=None)
    pi.set_defaults(func=cmd_record_iter)

    ps = sub.add_parser("record-scan")
    ps.add_argument("scan_id")
    ps.add_argument("target")
    ps.add_argument("candidate_class", nargs="?", default=None)
    ps.add_argument("verdict", nargs="?", default=None)
    ps.add_argument("evidence", nargs="?", default=None)
    ps.set_defaults(func=cmd_record_scan)

    pf = sub.add_parser("record-fix")
    pf.add_argument("iter_id")
    pf.add_argument("file")
    pf.add_argument("commit_sha", nargs="?", default=None)
    pf.add_argument("reason", nargs="?", default=None)
    pf.add_argument("expected", nargs="?", default=None)
    pf.set_defaults(func=cmd_record_fix)

    pt = sub.add_parser("record-test")
    pt.add_argument("iter_id")
    pt.add_argument("file")
    pt.add_argument("result")
    pt.add_argument("before", nargs="?", default=None)
    pt.add_argument("after", nargs="?", default=None)
    pt.set_defaults(func=cmd_record_test)

    psc = sub.add_parser("record-score")
    psc.add_argument("iter_id")
    psc.add_argument("scan_id", nargs="?", default=None)
    psc.add_argument("score")
    psc.add_argument("components", nargs="?", default=None)
    psc.set_defaults(func=cmd_record_score)

    pp = sub.add_parser("record-policy")
    pp.add_argument("arm")
    pp.add_argument("score")
    pp.set_defaults(func=cmd_record_policy)

    pe = sub.add_parser("record-external")
    pe.add_argument("platform")
    pe.add_argument("external_id")
    pe.add_argument("domain")
    pe.add_argument("finding_hash")
    pe.add_argument("status")
    pe.add_argument("triaged_at")
    pe.set_defaults(func=cmd_record_external)

    pce = sub.add_parser("count-external-closed")
    pce.add_argument("domain")
    pce.add_argument("--days", type=int, default=90)
    pce.set_defaults(func=cmd_count_external_closed)

    pl = sub.add_parser("last-iterations")
    pl.add_argument("n", nargs="?", type=int, default=20)
    pl.set_defaults(func=cmd_last_iterations)

    sub.add_parser("best-arm").set_defaults(func=cmd_best_arm)
    sub.add_parser("status").set_defaults(func=cmd_status)

    args = p.parse_args(argv)
    if not hasattr(args, "func"):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
