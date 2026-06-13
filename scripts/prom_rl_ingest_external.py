#!/usr/bin/env python3
"""prom_rl_ingest_external.py — Ingest external Bugcrowd/HackerOne submission
state into the local prometheus.db so future scans do not re-discover and
re-file findings the user has already submitted (and had rejected/closed).

Subcommands
-----------
bugcrowd <export.csv> [--dry-run]
    Ingest a Bugcrowd researcher-dashboard export CSV. Tolerant of column
    re-ordering and unknown columns. Each row is upserted into
    external_submissions by (platform, external_id). After each upsert
    the matching report_status row is updated via propagate_external_to_internal.

h1 <export.csv> [--dry-run]
    Same, but for a HackerOne researcher-dashboard export.

single --platform bugcrowd --external-id <id> --domain <d> --title <t> \
       --endpoint <e> --cwe <c> --status <s> --priority <p> \
       --triager <t> --report-url <u> --notes <n> [--reward-usd <r>]
    Ingest a single row. Used for backfill of known-closed reports.

list [--domain <d>] [--status <s>]
    Print external_submissions rows. Default: last 50 across all domains.

status
    One-shot summary: count by status, count by domain.

Design notes
-----------
- Uses the same KnowledgeStore singleton the agent uses. Safe to run
  while prometheus is running; the upserts are wrapped in a single
  connection's lock.
- The CSV parser is intentionally tolerant: header names are mapped
  to internal fields by a case-insensitive substring match. Unknown
  columns are logged and ignored, not errored.
- `--dry-run` prints the would-be rows but does not write.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

# Allow the script to be invoked from anywhere
SCRIPT_DIR = Path(__file__).resolve().parent
PROM_SRC = SCRIPT_DIR.parent
sys.path.insert(0, str(PROM_SRC))

from prometheus.tools.knowledge.store import KnowledgeStore  # noqa: E402


logger = logging.getLogger("prom_rl_ingest_external")
logging.basicConfig(
    level=os.environ.get("PROM_RL_INGEST_LOG", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)


# ---------------------------------------------------------------------------
# CSV column mapping: friendly header name (case-insensitive, substring) → field
# ---------------------------------------------------------------------------

_BC_COLUMN_MAP: dict[str, str] = {
    "submission id": "external_id",
    "id": "external_id",
    "report id": "external_id",
    "title": "finding_title",
    "vulnerability": "finding_title",
    "target": "endpoint",
    "endpoint": "endpoint",
    "url": "endpoint",
    "target location": "domain",
    "domain": "domain",
    "status": "status",
    "state": "status",
    "priority": "priority",
    "vrt": "cwe",
    "cwe": "cwe",
    "vrt category": "cwe",
    "reward": "reward_usd",
    "payout": "reward_usd",
    "bounty": "reward_usd",
    "report url": "report_url",
    "submitted": "submitted_at",
    "submitted at": "submitted_at",
    "closed": "triaged_at",
    "closed at": "triaged_at",
    "triaged at": "triaged_at",
    "triager": "triager",
    "researcher": "triager",
    "notes": "notes",
    "comments": "notes",
    "activity": "notes",
}

_H1_COLUMN_MAP: dict[str, str] = {
    "report id": "external_id",
    "id": "external_id",
    "title": "finding_title",
    "vulnerability type": "finding_title",
    "asset": "endpoint",
    "asset identifier": "endpoint",
    "url": "endpoint",
    "weakness": "cwe",
    "severity": "priority",
    "state": "status",
    "status": "status",
    "bounty": "reward_usd",
    "amount": "reward_usd",
    "disclosed": "triaged_at",
    "closed at": "triaged_at",
    "submitted at": "submitted_at",
    "researcher": "triager",
    "notes": "notes",
}


def _resolve_column(header: str, mapping: dict[str, str]) -> str | None:
    h = header.strip().lower()
    if h in mapping:
        return mapping[h]
    for key, val in mapping.items():
        if key in h:
            return val
    return None


def _row_to_args(row: dict[str, str], mapping: dict[str, str]) -> dict[str, Any]:
    """Map a CSV row dict to a kwargs dict for upsert_external_submission."""
    out: dict[str, Any] = {}
    for header, value in row.items():
        if value is None or value == "":
            continue
        field = _resolve_column(header, mapping)
        if not field:
            continue
        if field in ("reward_usd",):
            try:
                value = float(re.sub(r"[^\d.\-]", "", str(value)))
            except ValueError:
                continue
        out[field] = str(value).strip()
    return out


def _status_to_internal(status: str) -> str:
    """Map a platform's status string to one of the internal values
    external_submissions.status accepts."""
    s = (status or "").lower()
    if s in ("not applicable", "not_applicable", "na", "n/a"):
        return "na"
    if s in ("informative", "informational", "info"):
        return "informative"
    if s in ("not reproducible", "not_reproducible", "needs more info", "cant-reproduce"):
        return "not_reproducible"
    if s in ("resolved", "fixed", "patched", "closed"):
        return "resolved"
    if s in ("accepted", "bounty awarded", "paid", "resolved (accepted)"):
        return "accepted"
    if s in ("duplicate", "dupe"):
        return "duplicate"
    if s in ("triaging", "needs review", "triage"):
        return "triaged"
    if s in ("new", "open", "submitted"):
        return "submitted"
    if s in ("rejected",):
        return "rejected"
    return s or "submitted"


def _priority_to_internal(priority: str) -> str | None:
    p = (priority or "").strip().lower()
    if not p:
        return None
    # H1 uses 1.0-5.0 severity scale; Bugcrowd uses P1..P5
    if p.startswith("p") and p[1:].isdigit():
        return p.upper()
    if p in ("critical", "high", "medium", "low", "none", "informational"):
        return p
    try:
        f = float(p)
        if f <= 1.5:
            return "P1"
        if f <= 2.5:
            return "P2"
        if f <= 3.5:
            return "P3"
        if f <= 4.5:
            return "P4"
        return "P5"
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_ingest_csv(args: argparse.Namespace) -> int:
    """Ingest a CSV file. The platform determines the column map."""
    platform = args.platform
    if platform == "bugcrowd":
        mapping = _BC_COLUMN_MAP
    elif platform == "hackerone":
        mapping = _H1_COLUMN_MAP
    else:
        print(f"unknown platform: {platform}", file=sys.stderr)
        return 2
    path = Path(args.csv)
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 1
    ks = KnowledgeStore()
    created = 0
    updated = 0
    errors = 0
    with path.open() as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, 1):
            try:
                fields = _row_to_args(row, mapping)
                # Required: external_id, domain, finding_title
                if not fields.get("external_id"):
                    print(f"row {row_idx}: missing external_id, skipping", file=sys.stderr)
                    errors += 1
                    continue
                if not fields.get("domain"):
                    # Try to extract domain from endpoint
                    ep = fields.get("endpoint") or ""
                    m = re.search(r"https?://([^/]+)", ep)
                    if m:
                        fields["domain"] = m.group(1)
                    else:
                        print(f"row {row_idx}: missing domain, skipping", file=sys.stderr)
                        errors += 1
                        continue
                if not fields.get("finding_title"):
                    print(f"row {row_idx}: missing finding_title, skipping", file=sys.stderr)
                    errors += 1
                    continue
                if fields.get("status"):
                    fields["status"] = _status_to_internal(fields["status"])
                if fields.get("priority"):
                    fields["priority"] = _priority_to_internal(fields["priority"])
                if not fields.get("endpoint"):
                    # Synthesize endpoint from domain
                    fields["endpoint"] = f"https://{fields['domain']}"
                if args.dry_run:
                    print(f"[dry-run] would upsert: {fields.get('external_id')} {fields.get('finding_title')[:60]!r} status={fields.get('status')}")
                    continue
                result = ks.upsert_external_submission(platform=platform, **fields)
                ks.propagate_external_to_internal(platform=platform, external_id=fields["external_id"])
                if result.get("action") == "created":
                    created += 1
                else:
                    updated += 1
            except Exception as e:  # noqa: BLE001
                print(f"row {row_idx}: {e}", file=sys.stderr)
                errors += 1
    print(f"created={created} updated={updated} errors={errors}")
    return 0 if errors == 0 else 1


def cmd_single(args: argparse.Namespace) -> int:
    """Ingest a single row. Used for backfill and one-off triager responses."""
    if not args.external_id:
        print("--external-id is required", file=sys.stderr)
        return 2
    if not args.platform:
        print("--platform is required", file=sys.stderr)
        return 2
    if not args.domain:
        print("--domain is required", file=sys.stderr)
        return 2
    if not args.title:
        print("--title is required", file=sys.stderr)
        return 2
    ks = KnowledgeStore()
    fields: dict[str, Any] = {
        "platform": args.platform,
        "external_id": args.external_id,
        "domain": args.domain,
        "finding_title": args.title,
        "endpoint": args.endpoint or f"https://{args.domain}",
        "cwe": args.cwe or "",
        "status": _status_to_internal(args.status or "submitted"),
        "priority": _priority_to_internal(args.priority) if args.priority else None,
        "triager": args.triager,
        "report_url": args.report_url,
        "triaged_at": args.triaged_at,
        "notes": args.notes,
        "reward_usd": args.reward_usd,
    }
    if args.dry_run:
        print(f"[dry-run] would upsert: {json.dumps(fields, default=str, indent=2)}")
        return 0
    result = ks.upsert_external_submission(**fields)
    prop = ks.propagate_external_to_internal(platform=args.platform, external_id=args.external_id)
    print(f"external_submissions: action={result.get('action')} id={result.get('id')}")
    print(f"propagate: action={prop.get('action')} report_status_id={prop.get('report_status_id')}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    ks = KnowledgeStore()
    rows = ks.list_external_submissions(domain=args.domain, status=args.status, limit=args.limit)
    if not rows:
        print("no external_submissions rows")
        return 0
    for r in rows:
        title = (r.get("finding_title") or "")[:60]
        print(
            f"  [{r.get('platform'):10s}] {r.get('external_id')[:40]:40s} "
            f"status={r.get('status'):20s} domain={r.get('domain'):30s} {title!r}"
        )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    ks = KnowledgeStore()
    rows = ks.list_external_submissions(limit=10000)
    if not rows:
        print("external_submissions table: 0 rows")
        return 0
    by_status: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    by_domain: dict[str, int] = {}
    for r in rows:
        by_status[r.get("status") or "?"] = by_status.get(r.get("status") or "?", 0) + 1
        by_platform[r.get("platform") or "?"] = by_platform.get(r.get("platform") or "?", 0) + 1
        by_domain[r.get("domain") or "?"] = by_domain.get(r.get("domain") or "?", 0) + 1
    print(f"external_submissions: {len(rows)} total rows")
    print()
    print("by status:")
    for k, v in sorted(by_status.items(), key=lambda x: -x[1]):
        print(f"  {k:30s} {v}")
    print()
    print("by platform:")
    for k, v in sorted(by_platform.items(), key=lambda x: -x[1]):
        print(f"  {k:30s} {v}")
    print()
    print("by domain (top 20):")
    for k, v in sorted(by_domain.items(), key=lambda x: -x[1])[:20]:
        print(f"  {k:40s} {v}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest external Bugcrowd/HackerOne submission state")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_bc = sub.add_parser("bugcrowd", help="Ingest a Bugcrowd researcher-dashboard export CSV")
    p_bc.add_argument("csv", help="Path to the export CSV")
    p_bc.add_argument("--dry-run", action="store_true", help="Print but do not write")
    p_bc.set_defaults(func=lambda a: cmd_ingest_csv(argparse.Namespace(platform="bugcrowd", csv=a.csv, dry_run=a.dry_run)))

    p_h1 = sub.add_parser("h1", help="Ingest a HackerOne researcher-dashboard export CSV")
    p_h1.add_argument("csv", help="Path to the export CSV")
    p_h1.add_argument("--dry-run", action="store_true", help="Print but do not write")
    p_h1.set_defaults(func=lambda a: cmd_ingest_csv(argparse.Namespace(platform="hackerone", csv=a.csv, dry_run=a.dry_run)))

    p_single = sub.add_parser("single", help="Ingest a single row by CLI args")
    p_single.add_argument("--platform", required=True, choices=["bugcrowd", "hackerone"])
    p_single.add_argument("--external-id", required=True)
    p_single.add_argument("--domain", required=True)
    p_single.add_argument("--title", required=True)
    p_single.add_argument("--endpoint", default="")
    p_single.add_argument("--cwe", default="")
    p_single.add_argument("--status", default="submitted")
    p_single.add_argument("--priority", default="")
    p_single.add_argument("--triager", default="")
    p_single.add_argument("--report-url", default="")
    p_single.add_argument("--triaged-at", default="")
    p_single.add_argument("--notes", default="")
    p_single.add_argument("--reward-usd", type=float, default=None)
    p_single.add_argument("--dry-run", action="store_true")
    p_single.set_defaults(func=cmd_single)

    p_list = sub.add_parser("list", help="List external_submissions rows")
    p_list.add_argument("--domain", default=None)
    p_list.add_argument("--status", default=None)
    p_list.add_argument("--limit", type=int, default=50)
    p_list.set_defaults(func=cmd_list)

    sub.add_parser("status", help="One-shot summary").set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
