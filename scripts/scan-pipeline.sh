#!/bin/bash
# Prometheus deterministic scan pipeline
# Runs recon → fingerprint → scan in one shot, no LLM turns between steps.
# The agent calls this ONCE instead of making 5-10 individual LLM tool calls.
#
# Usage: scan-pipeline.sh <target_url> <output_dir> [--tor] [--allow-direct] [--deep]
#   --tor             Route traffic through Tor proxy
#   --allow-direct    If Tor is unavailable, allow direct fallback per tool
#   --deep            Run deeper scanning (nuclei exhaustive + sqlmap basic check)
#
# Reads PROMETHEUS_TOR_PROXY env var for Tor SOCKS5 address (default: socks5://[IP_ADDRESS]:9050)
# Reads PROMETHEUS_ALLOW_DIRECT env var for fallback permission
set -euo pipefail

TARGET="${1:?Usage: scan-pipeline.sh <target_url> <output_dir> [--tor] [--allow-direct] [--deep]}"
OUTDIR="${2:?Usage: scan-pipeline.sh <target_url> <output_dir> [--tor] [--allow-direct] [--deep]}"
shift 2

USE_TOR=false
ALLOW_DIRECT=false
DEEP=false
while [ $# -gt 0 ]; do
    case "$1" in
        --tor) USE_TOR=true ;;
        --allow-direct) ALLOW_DIRECT=true ;;
        --deep) DEEP=true ;;
    esac
    shift
done

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/pipeline-summary.json"
TIMESTAMP=$(date -Iseconds)

# Tor proxy config from env var with fallback
TOR_PROXY="${PROMETHEUS_TOR_PROXY:-socks5://[IP_ADDRESS]:9050}"
PROXY_FLAGS=""
NO_PROXY_FLAGS=""
if $USE_TOR; then
    PROXY_FLAGS="--proxy $TOR_PROXY"
    export HTTP_PROXY="$TOR_PROXY"
    export HTTPS_PROXY="$TOR_PROXY"
    ALL_PROXY="$TOR_PROXY"
fi

echo "=== PIPELINE START [$TIMESTAMP] ===" | tee "$OUTDIR/pipeline.log"
echo "Target: $TARGET" | tee -a "$OUTDIR/pipeline.log"
echo "Tor: $USE_TOR  AllowDirect: $ALLOW_DIRECT  Deep: $DEEP" | tee -a "$OUTDIR/pipeline.log"
echo "" | tee -a "$OUTDIR/pipeline.log"

# Helper: run a command, optionally retry without proxy on failure
run_with_retry() {
    local label="$1"
    local cmd="$2"
    local outfile="$3"
    local fail_value="$4"
    local retry_cmd="$5"

    echo "  Running $label..." | tee -a "$OUTDIR/pipeline.log"
    eval "$cmd" 2>>"$OUTDIR/pipeline.log" || {
        local ec=$?
        if $ALLOW_DIRECT && [ -n "$PROXY_FLAGS" ]; then
            echo "  $label failed (exit $ec) via Tor, retrying directly..." | tee -a "$OUTDIR/pipeline.log"
            unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
            eval "$retry_cmd" 2>>"$OUTDIR/pipeline.log" || {
                echo "  $label also failed directly." | tee -a "$OUTDIR/pipeline.log"
                echo "$fail_value" > "$outfile"
            }
            export HTTP_PROXY="$TOR_PROXY"
            export HTTPS_PROXY="$TOR_PROXY"
            ALL_PROXY="$TOR_PROXY"
        else
            echo "$fail_value" > "$outfile"
        fi
    }
}

# ── Phase 1: HTTP Probing & Technology Detection ──
echo "--- Phase 1: HTTP Probing ---" | tee -a "$OUTDIR/pipeline.log"
if command -v httpx &>/dev/null; then
    run_with_retry \
        "httpx" \
        "httpx -u \"$TARGET\" -tech-detect -title -status-code -websocket \
            -ip -cname -cdn -server -content-type -location \
            $PROXY_FLAGS -silent -json > \"$OUTDIR/httpx.json\"" \
        "$OUTDIR/httpx.json" "[]" \
        "httpx -u \"$TARGET\" -tech-detect -title -status-code -websocket \
            -ip -cname -cdn -server -content-type -location \
            -silent -json > \"$OUTDIR/httpx.json\""
    echo "  httpx: $(python3 -c "import json; d=json.load(open('$OUTDIR/httpx.json')); print(len(d) if isinstance(d,list) else 1)") results" | tee -a "$OUTDIR/pipeline.log"
else
    echo "  httpx: NOT INSTALLED" | tee -a "$OUTDIR/pipeline.log"
    echo '[]' > "$OUTDIR/httpx.json"
fi

if command -v whatweb &>/dev/null; then
    whatweb "$TARGET" --log-json="$OUTDIR/whatweb.json" --no-errors -q 2>>"$OUTDIR/pipeline.log" || echo '[]' > "$OUTDIR/whatweb.json"
    echo "  whatweb: done" | tee -a "$OUTDIR/pipeline.log"
else
    echo "  whatweb: NOT INSTALLED" | tee -a "$OUTDIR/pipeline.log"
    echo '[]' > "$OUTDIR/whatweb.json"
fi

# ── Phase 2: Port Scanning ──
echo "--- Phase 2: Port Scan ---" | tee -a "$OUTDIR/pipeline.log"
HOST=$(echo "$TARGET" | sed -E 's|^https?://||;s|/.*||;s|:.*||')
if command -v nmap &>/dev/null; then
    nmap -sV -sC -Pn --top-ports 1000 -oA "$OUTDIR/nmap" "$HOST" 2>>"$OUTDIR/pipeline.log" || true
    echo "  nmap: $(grep -c 'open' "$OUTDIR/nmap.nmap" 2>/dev/null || echo 0) open ports" | tee -a "$OUTDIR/pipeline.log"
else
    echo "  nmap: NOT INSTALLED" | tee -a "$OUTDIR/pipeline.log"
fi

if command -v naabu &>/dev/null; then
    run_with_retry \
        "naabu" \
        "naabu -host \"$HOST\" $PROXY_FLAGS -silent -json > \"$OUTDIR/naabu.json\"" \
        "$OUTDIR/naabu.json" "[]" \
        "naabu -host \"$HOST\" -silent -json > \"$OUTDIR/naabu.json\""
    echo "  naabu: $(python3 -c "import json; d=json.load(open('$OUTDIR/naabu.json')); print(len(d) if isinstance(d,list) else 0)") ports" | tee -a "$OUTDIR/pipeline.log"
fi

# ── Phase 3: Directory Enumeration ──
echo "--- Phase 3: Directory Enumeration ---" | tee -a "$OUTDIR/pipeline.log"
if command -v dirsearch &>/dev/null; then
    run_with_retry \
        "dirsearch" \
        "dirsearch -u \"$TARGET\" -e php,html,js,json,asp,aspx,jsp,xml,yml,yaml,env,bak,backup,old,zip,tar.gz,sql,db \
            --no-color --format=json -o \"$OUTDIR/dirsearch.json\" \
            $PROXY_FLAGS -q" \
        "$OUTDIR/dirsearch.json" "[]" \
        "dirsearch -u \"$TARGET\" -e php,html,js,json,asp,aspx,jsp,xml,yml,yaml,env,bak,backup,old,zip,tar.gz,sql,db \
            --no-color --format=json -o \"$OUTDIR/dirsearch.json\" -q"
    echo "  dirsearch: done" | tee -a "$OUTDIR/pipeline.log"
else
    echo "  dirsearch: NOT INSTALLED" | tee -a "$OUTDIR/pipeline.log"
    echo '[]' > "$OUTDIR/dirsearch.json"
fi

if command -v ffuf &>/dev/null; then
    if [ -f /usr/share/wordlists/dirb/common.txt ]; then
        WORDLIST=/usr/share/wordlists/dirb/common.txt
    elif [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
        WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
    else
        WORDLIST=/dev/null
    fi
    if [ "$WORDLIST" != "/dev/null" ]; then
        run_with_retry \
            "ffuf" \
            "ffuf -u \"${TARGET}/FUZZ\" -w \"$WORDLIST\" -mc 200,204,301,302,307,401,403,405 \
                -o \"$OUTDIR/ffuf.json\" -of json -s $PROXY_FLAGS" \
            "$OUTDIR/ffuf.json" "{}" \
            "ffuf -u \"${TARGET}/FUZZ\" -w \"$WORDLIST\" -mc 200,204,301,302,307,401,403,405 \
                -o \"$OUTDIR/ffuf.json\" -of json -s"
        echo "  ffuf: done" | tee -a "$OUTDIR/pipeline.log"
    fi
fi

# ── Phase 4: Vulnerability Scanning ──
echo "--- Phase 4: Vulnerability Scan ---" | tee -a "$OUTDIR/pipeline.log"
if command -v nuclei &>/dev/null; then
    SEVERITY="-severity critical,high,medium"
    if $DEEP; then
        SEVERITY="-severity critical,high,medium,low"
    fi
    run_with_retry \
        "nuclei" \
        "nuclei -u \"$TARGET\" $SEVERITY -timeout 15 -retries 1 \
            $PROXY_FLAGS -no-interactsh -no-httpx -rate-limit 5 -c 10 \
            -json -silent -o \"$OUTDIR/nuclei.json\"" \
        "$OUTDIR/nuclei.json" "[]" \
        "nuclei -u \"$TARGET\" $SEVERITY -timeout 15 -retries 1 \
            -no-interactsh -no-httpx -rate-limit 5 -c 10 \
            -json -silent -o \"$OUTDIR/nuclei.json\""
    echo "  nuclei: $(python3 -c "import json; d=json.load(open('$OUTDIR/nuclei.json')); print(len(d) if isinstance(d,list) else 0)") findings" | tee -a "$OUTDIR/pipeline.log"
else
    echo "  nuclei: NOT INSTALLED" | tee -a "$OUTDIR/pipeline.log"
    echo '[]' > "$OUTDIR/nuclei.json"
fi

# ── Phase 5: WAF Detection ──
echo "--- Phase 5: WAF Detection ---" | tee -a "$OUTDIR/pipeline.log"
if command -v wafw00f &>/dev/null; then
    run_with_retry \
        "wafw00f" \
        "wafw00f \"$TARGET\" -o \"$OUTDIR/wafw00f.json\" -f json" \
        "$OUTDIR/wafw00f.json" "{}" \
        "wafw00f \"$TARGET\" -o \"$OUTDIR/wafw00f.json\" -f json"
    echo "  wafw00f: done" | tee -a "$OUTDIR/pipeline.log"
else
    echo "  wafw00f: NOT INSTALLED" | tee -a "$OUTDIR/pipeline.log"
    echo '{}' > "$OUTDIR/wafw00f.json"
fi

# ── Phase 6: Deep (optional) ──
if $DEEP; then
    echo "--- Phase 6: Deep Scan ---" | tee -a "$OUTDIR/pipeline.log"
    if command -v sqlmap &>/dev/null; then
        if $ALLOW_DIRECT && [ -n "$PROXY_FLAGS" ]; then
            unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
        fi
        sqlmap -u "$TARGET" --batch --smart --level=2 --risk=2 \
            --output-dir="$OUTDIR/sqlmap" \
            --threads=4 --timeout=10 2>>"$OUTDIR/pipeline.log" || true
        if $ALLOW_DIRECT && [ -n "$PROXY_FLAGS" ]; then
            export HTTP_PROXY="$TOR_PROXY"
            export HTTPS_PROXY="$TOR_PROXY"
        fi
        echo "  sqlmap: done" | tee -a "$OUTDIR/pipeline.log"
    fi
fi

# ── Build Summary ──
echo "--- Building Summary ---" | tee -a "$OUTDIR/pipeline.log"
python3 -c "
import json, os, glob

def safe_load(path, default=None):
    if default is None:
        default = []
    try:
        if not os.path.exists(path):
            return default
        with open(path) as f:
            data = json.load(f)
        return data if data is not None else default
    except:
        return default

summary = {
    'target': '$TARGET',
    'timestamp': '$TIMESTAMP',
    'phases': {}
}

# Phase 1
httpx_data = safe_load('$OUTDIR/httpx.json')
whatweb_data = safe_load('$OUTDIR/whatweb.json')
tech_set = set()
for item in (httpx_data if isinstance(httpx_data, list) else [httpx_data]):
    tech_str = item.get('tech', '') or item.get('technologies', '') or ''
    if isinstance(tech_str, list):
        tech_set.update(tech_str)
    elif tech_str:
        tech_set.update(t.strip() for t in tech_str.split(',') if t.strip())
summary['phases']['recon'] = {
    'httpx_results': len(httpx_data) if isinstance(httpx_data, list) else (1 if httpx_data else 0),
    'technologies_detected': list(tech_set)[:50],
    'tech_count': len(tech_set),
}

# Phase 2
nmap_file = '$OUTDIR/nmap.nmap'
open_ports = 0
if os.path.exists(nmap_file):
    with open(nmap_file) as f:
        for line in f:
            if 'open' in line.lower().split():
                open_ports += 1
summary['phases']['port_scan'] = {
    'open_ports': open_ports,
}

# Phase 3
dirsearch_data = safe_load('$OUTDIR/dirsearch.json')
ffuf_data = safe_load('$OUTDIR/ffuf.json', {})
summary['phases']['dir_enum'] = {
    'dirsearch_results': len(dirsearch_data) if isinstance(dirsearch_data, list) else 0,
    'ffuf_results': len(ffuf_data.get('results', [])) if isinstance(ffuf_data, dict) else 0,
}

# Phase 4
nuclei_data = safe_load('$OUTDIR/nuclei.json')
nuclei_findings = []
for n in (nuclei_data if isinstance(nuclei_data, list) else []):
    nuclei_findings.append({
        'name': n.get('info', {}).get('name', n.get('template-id', '')),
        'severity': n.get('info', {}).get('severity', n.get('severity', '')),
        'matched': n.get('matched-at', n.get('matched', '')),
        'type': n.get('type', ''),
    })
summary['phases']['vuln_scan'] = {
    'nuclei_findings': len(nuclei_findings),
    'top_findings': nuclei_findings[:10],
}

# Phase 5
waf_data = safe_load('$OUTDIR/wafw00f.json', {})
waf_detected = ''
if isinstance(waf_data, list) and len(waf_data) > 0:
    waf_detected = waf_data[0].get('waf', '') or ''
elif isinstance(waf_data, dict):
    waf_detected = waf_data.get('waf', '') or str(waf_data.get('detected', ''))
summary['phases']['waf'] = {
    'detected': bool(waf_detected),
    'waf_name': str(waf_detected)[:100],
}

json.dump(summary, open('$SUMMARY', 'w'), indent=2, default=str)
print(f'Pipeline complete. {len(tech_set)} technologies detected, {open_ports} open ports, {len(nuclei_findings)} nuclei findings.')
" | tee -a "$OUTDIR/pipeline.log"

echo "=== PIPELINE COMPLETE ===" | tee -a "$OUTDIR/pipeline.log"
echo "Summary: $SUMMARY" | tee -a "$OUTDIR/pipeline.log"
cat "$SUMMARY"
