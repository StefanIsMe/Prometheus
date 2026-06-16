#!/usr/bin/env python3
"""Daily threat intelligence summary — reads from /tmp/prometheus-threat-intel/ and outputs a digest."""

import json
import logging
import os
import glob
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

FEED_DIR = os.path.join(
    os.environ.get("PROMETHEUS_DATA_DIR", os.path.expanduser("~/.prometheus")),
    "threat-intel",
)
now = datetime.now()
cutoff_24h = (now - timedelta(hours=24)).isoformat()
cutoff_7d = (now - timedelta(days=7)).strftime("%Y-%m-%d")

lines = []
lines.append(f"🔴 Daily Threat Intel — {now.strftime('%Y-%m-%d %H:%M')} ICT")
lines.append("")

# --- CISA KEV (new entries in last 7 days) ---
try:
    with open(os.path.join(FEED_DIR, "cisa-kev.json")) as _kev_f:
        kev = json.load(_kev_f)
    vulns = kev.get("vulnerabilities", [])
    recent = [v for v in vulns if v.get("dateAdded", "") >= cutoff_7d]
    lines.append(f"📋 CISA KEV: {len(vulns)} total, {len(recent)} added this week")
    if recent:
        for v in recent[:10]:
            lines.append(
                f"  • {v['cveID']} — {v.get('vendorProject', '')} {v.get('product', '')} ({v.get('dateAdded', '')})"
            )
        if len(recent) > 10:
            lines.append(f"  ... and {len(recent) - 10} more")
    lines.append("")
except Exception as e:
    lines.append(f"📋 CISA KEV: error — {e}")
    lines.append("")

# --- GHSA (recent high/critical) ---
try:
    ghsa_all = []
    seen = set()
    for f in sorted(glob.glob(os.path.join(FEED_DIR, "ghsa-*.json"))):
        with open(f) as _ghsa_f:
            data = json.load(_ghsa_f)
        if isinstance(data, list):
            for a in data:
                aid = a.get("ghsa_id", "")
                if aid and aid not in seen:
                    seen.add(aid)
                    published = a.get("published_at", "")
                    if published and published >= cutoff_24h:
                        ghsa_all.append(a)

    lines.append(f"🐙 GitHub Advisories: {len(ghsa_all)} new high/critical in last 24h")
    if ghsa_all:
        for a in sorted(ghsa_all, key=lambda x: x.get("published_at", ""), reverse=True)[:10]:
            cve = next(
                (i.get("value", "") for i in a.get("identifiers", []) if i.get("type") == "CVE"),
                a.get("ghsa_id", ""),
            )
            lines.append(
                f"  • [{a.get('severity', '').upper()}] {cve} — {a.get('summary', '')[:80]}"
            )
        if len(ghsa_all) > 10:
            lines.append(f"  ... and {len(ghsa_all) - 10} more")
    lines.append("")
except Exception as e:
    lines.append(f"🐙 GHSA: error — {e}")
    lines.append("")

# --- NVD recent ---
try:
    nvd_total = 0
    nvd_vulns = []
    for f in glob.glob(os.path.join(FEED_DIR, "nvd-recent-*.json")):
        with open(f) as _nvd_f:
            data = json.load(_nvd_f)
        nvd_total += data.get("totalResults", 0)
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            published = cve.get("published", "")
            if published and published >= cutoff_24h:
                nvd_vulns.append(cve)

    lines.append(
        f"🗃️ NVD: {nvd_total} high/critical CVEs in last 48h, {len(nvd_vulns)} published today"
    )
    if nvd_vulns:
        for cve in sorted(nvd_vulns, key=lambda c: c.get("published", ""), reverse=True)[:10]:
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:80]
                    break
            # Get severity
            metrics = cve.get("metrics", {})
            score = "?"
            for mk in ("cvssMetricV31", "cvssMetricV30"):
                ml = metrics.get(mk, [])
                if ml:
                    score = ml[0].get("cvssData", {}).get("baseScore", "?")
                    break
            lines.append(f"  • [{score}] {cve_id} — {desc}")
        if len(nvd_vulns) > 10:
            lines.append(f"  ... and {len(nvd_vulns) - 10} more")
    lines.append("")
except Exception as e:
    lines.append(f"🗃️ NVD: error — {e}")
    lines.append("")

# --- Local cached summary ---
try:
    with open(os.path.join(FEED_DIR, "threat-summary.json")) as _summary_f:
        summary = json.load(_summary_f)
    lines.append(
        f"📊 Total across all feeds: {sum(v.get('total', 0) if isinstance(v, dict) else 0 for v in summary['sources'].values())} entries"
    )
except BaseException:  # codeql[py/catch-base-exception] : suppressed via the security dashboard triage
    logger.debug("could not load cached threat-summary.json, ignoring", exc_info=True)

output = "\n".join(lines)
print(output)
