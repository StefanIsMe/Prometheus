#!/usr/bin/env python3
"""Refresh local threat intelligence database from all online sources.

Usage:
    python3 refresh_threat_intel.py              # Refresh all feeds
    python3 refresh_threat_intel.py --feed epss  # Refresh specific feed
    python3 refresh_threat_intel.py --stats      # Show DB stats only

Exit codes:
    0 = success
    1 = one or more feeds failed
"""

import argparse
import json
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("refresh_threat_intel")

# Add prometheus source to path
import os

sys.path.insert(0, os.path.expanduser("~/prometheus-source"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh threat intelligence database")
    parser.add_argument("--feed", help="Refresh specific feed only", default=None)
    parser.add_argument("--stats", action="store_true", help="Show DB stats only")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    from prometheus.tools.threat_intel.local_db import ThreatIntelDB

    db = ThreatIntelDB()

    if args.stats:
        stats = db.get_stats()
        if args.json:
            print(json.dumps(stats, indent=2, default=str))
        else:
            print(f"Threat Intel DB: {stats['db_path']}")
            print(f"  Total CVEs: {stats['total_cves']:,}")
            print(f"  Total packages: {stats['total_packages']:,}")
            print(f"  Total references: {stats['total_references']:,}")
            print(f"  CISA KEV: {stats['cisa_kev_count']:,}")
            print(f"  With exploits: {stats['exploit_count']:,}")
            print(f"  With EPSS scores: {stats['epss_count']:,}")
            print(f"  Severity breakdown: {stats['severity_breakdown']}")
            print(f"  Ecosystem breakdown: {stats['ecosystem_breakdown']}")
            if stats["feeds"]:
                print("  Feeds:")
                for f in stats["feeds"]:
                    print(
                        f"    {f['feed_name']}: {f['status']} ({f['record_count']} records, {f.get('duration_seconds', 0):.1f}s)"
                    )
        db.close()
        return 0

    from prometheus.tools.threat_intel.feeds import (
        ingest_all,
        ingest_epss,
        ingest_cisa_kev,
        ingest_nvd_recent,
        ingest_ghsa_bulk,
        ingest_shodan_recent,
        ingest_circl_recent,
        ingest_cisa_advisories,
        ingest_exploitdb,
        ingest_wordfence,
        ingest_vulners_recent,
    )

    if args.feed:
        # Refresh single feed
        feed_map = {
            "epss": ingest_epss,
            "cisa_kev": ingest_cisa_kev,
            "nvd": lambda db: ingest_nvd_recent(db, days=7),
            "ghsa": ingest_ghsa_bulk,
            "shodan": ingest_shodan_recent,
            "circl": ingest_circl_recent,
            "cisa_advisories": ingest_cisa_advisories,
            "exploitdb": ingest_exploitdb,
            "wordfence": ingest_wordfence,
            "vulners": ingest_vulners_recent,
        }
        if args.feed not in feed_map:
            print(f"Unknown feed: {args.feed}")
            print(f"Available: {', '.join(feed_map.keys())}")
            db.close()
            return 1

        result = feed_map[args.feed](db)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"{args.feed}: {result.get('status')} ({result.get('count', 0)} records)")
        db.close()
        return 0 if result.get("status") != "error" else 1

    # Refresh all feeds
    print("Refreshing all threat intelligence feeds...")
    summary = ingest_all(db)

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(f"\n{'=' * 60}")
        print(f"Threat Intel Refresh Complete")
        print(f"{'=' * 60}")
        print(f"Total records: {summary['total_records']:,}")
        print(f"Duration: {summary['total_duration']:.1f}s")
        print(f"Errors: {len(summary['errors'])}")
        print()
        for name, result in summary["feeds"].items():
            status = result.get("status", "?")
            count = result.get("count", 0)
            dur = result.get("duration", 0)
            icon = "OK" if status == "ok" else "SKIP" if status == "skipped" else "FAIL"
            print(f"  [{icon}] {name}: {count:,} records ({dur:.1f}s)")
            if status == "error":
                print(f"       Error: {result.get('error', 'unknown')}")
        print()
        stats = summary.get("db_stats", {})
        print(
            f"DB totals: {stats.get('total_cves', 0):,} CVEs, {stats.get('total_packages', 0):,} packages"
        )

    db.close()
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
