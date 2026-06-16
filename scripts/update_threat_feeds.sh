#!/bin/bash
# Update Prometheus threat intelligence feeds
# Sources: CISA KEV, GitHub Security Advisories (GHSA), NVD trending CVEs
set -euo pipefail

FEED_DIR="${PROMETHEUS_DATA_DIR:-$HOME/.prometheus}/threat-intel"
mkdir -p "$FEED_DIR"
LOG="$FEED_DIR/update.log"
TODAY=$(date -Iseconds)

log() { echo "[$TODAY] $1" >> "$LOG"; echo "$1"; }

log "Starting threat feed update..."

# --- CISA KEV Catalog ---
if curl -sf --max-time 30 \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
    -o "$FEED_DIR/cisa-kev.json"; then
    VULN_COUNT=$(python3 -c "import json; print(len(json.load(open('$FEED_DIR/cisa-kev.json')).get('vulnerabilities',[])))" 2>/dev/null || echo "?")
    log "CISA KEV updated: $VULN_COUNT vulnerabilities"
else
    log "CISA KEV download FAILED"
fi

# --- GitHub Security Advisories (GHSA) ---
# Fetch recent high and critical advisories across key ecosystems
# Use gh CLI for authenticated requests (5000 req/hour vs 60 unauthenticated)
GH_AUTHED=""
if command -v gh &>/dev/null && gh auth status &>/dev/null 2>&1; then
    GH_AUTHED="yes"
    log "Using gh CLI for authenticated GHSA requests"
else
    log "WARNING: gh CLI not available — GHSA requests unauthenticated (60 req/hour)"
fi

for ecosystem in npm pip go maven nuget rubygems rust composer; do
    for severity in high critical; do
        if [ -n "$GH_AUTHED" ]; then
            # gh api handles auth automatically
            gh api "advisories?ecosystem=$ecosystem&severity=$severity&per_page=100&sort=published&direction=desc" \
                --hostname github.com \
                -H "Accept: application/vnd.github+json" \
                > "$FEED_DIR/ghsa-${ecosystem}-${severity}.json" 2>/dev/null || true
        else
            curl -sf --max-time 20 \
                "https://api.github.com/advisories?ecosystem=$ecosystem&severity=$severity&per_page=100&sort=published&direction=desc" \
                -H "Accept: application/vnd.github+json" \
                -o "$FEED_DIR/ghsa-${ecosystem}-${severity}.json" 2>/dev/null || true
        fi
    done
done
GHSA_COUNT=$(python3 -c "
import json, glob
seen = set()
for f in sorted(glob.glob('$FEED_DIR/ghsa-*.json')):
    try:
        data = json.load(open(f))
        if isinstance(data, list):
            for a in data:
                aid = a.get('ghsa_id', '')
                if aid: seen.add(aid)
    except: pass
print(len(seen))
" 2>/dev/null || echo "?")
log "GHSA updated: $GHSA_COUNT unique advisories"

# --- NVD Recent CVEs (last 48h, high/critical) ---
NVD_END=$(date -u +%Y-%m-%dT%H:%M:%S.000)
NVD_START=$(date -u -d "2 days ago" +%Y-%m-%dT%H:%M:%S.000 2>/dev/null || echo "")
if [ -n "$NVD_START" ]; then
    # NVD only allows one severity per request
    for sev in HIGH CRITICAL; do
        curl -sf --max-time 30 \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=$NVD_START&pubEndDate=$NVD_END&cvssV3Severity=$sev&resultsPerPage=100" \
            -o "$FEED_DIR/nvd-recent-${sev,,}.json" 2>/dev/null || true
    done
    NVD_COUNT=$(python3 -c "
import json, os
total = 0
for f in ['nvd-recent-high.json', 'nvd-recent-critical.json']:
    try:
        d = json.load(open(os.path.join('$FEED_DIR', f)))
        total += d.get('totalResults', 0)
    except: pass
print(total)
" 2>/dev/null || echo "?")
    log "NVD recent (last 2d, high+critical): $NVD_COUNT CVEs"
else
    log "NVD: could not compute date range, skipping"
fi

# --- Merge into summary ---
python3 -c "
import json, os, glob
from datetime import datetime, timedelta

feed_dir = '$FEED_DIR'
summary = {
    'updated': '$TODAY',
    'sources': {}
}

# CISA KEV
try:
    kev = json.load(open(os.path.join(feed_dir, 'cisa-kev.json')))
    vulns = kev.get('vulnerabilities', [])
    cutoff = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    recent = [v for v in vulns if v.get('dateAdded', '') >= cutoff]
    summary['sources']['cisa_kev'] = {
        'total': len(vulns),
        'added_last_7d': len(recent),
        'recent_cves': [{'cve': v['cveID'], 'product': v.get('product',''), 'added': v.get('dateAdded','')} for v in recent[:20]]
    }
except Exception as e:
    summary['sources']['cisa_kev'] = {'error': str(e)}

# GHSA
ghsa_all = []
seen_ghsa = set()
for f in glob.glob(os.path.join(feed_dir, 'ghsa-*.json')):
    try:
        data = json.load(open(f))
        if isinstance(data, list):
            for a in data:
                aid = a.get('ghsa_id', '')
                if aid and aid not in seen_ghsa:
                    seen_ghsa.add(aid)
                    ghsa_all.append(a)
    except: pass
if ghsa_all:
    summary['sources']['ghsa'] = {
        'total': len(ghsa_all),
        'recent': [{'id': a.get('ghsa_id',''), 'cve': next((x for x in a.get('identifiers',[]) if x.get('type')=='CVE'), {}).get('value',''), 'summary': a.get('summary','')[:100], 'severity': a.get('severity',''), 'published': a.get('published_at','')} for a in ghsa_all[:30]]
    }

# NVD
nvd_total = 0
nvd_recent = []
for f in ['nvd-recent-high.json', 'nvd-recent-critical.json']:
    try:
        nvd = json.load(open(os.path.join(feed_dir, f)))
        nvd_total += nvd.get('totalResults', 0)
        for v in nvd.get('vulnerabilities', [])[:10]:
            cve = v.get('cve', {})
            nvd_recent.append({'cve': cve.get('id',''), 'published': cve.get('published','')})
    except: pass
if nvd_total > 0:
    summary['sources']['nvd_recent'] = {
        'total': nvd_total,
        'recent': nvd_recent[:20]
    }

json.dump(summary, open(os.path.join(feed_dir, 'threat-summary.json'), 'w'), indent=2)
total_all = sum(v.get('total', 0) if isinstance(v, dict) else 0 for v in summary['sources'].values())
print(f'Summary: {total_all} entries across {len(summary[\"sources\"])} sources')
" 2>/dev/null && log "Threat summary written" || log "Summary generation failed"

log "Feed update complete"
