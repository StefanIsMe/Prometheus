#!/bin/bash
# Nuclei scan through Tor with WAF-aware tuning and structured output
# Usage: nuclei_tor_scan.sh <target_url> [output_file] [extra_args...]
#
# Reads PROMETHEUS_TOR_PROXY env var for Tor address (default: socks5://[IP_ADDRESS]:9050)
# Reads PROMETHEUS_ALLOW_DIRECT env var (true/false) for fallback behavior
#
# Improvements over basic nuclei:
#  - Pre-flight check: detects if target is WAF-blocked before full scan
#  - --no-httpx: skips redundant HTTP probe (already done by pipeline)
#  - Skips template paths that trigger WAFs on CDN-protected targets
#  - JSON output for structured parsing
#  - Classifies results as real findings vs WAF noise

set -euo pipefail

TARGET="${1:?Usage: nuclei_tor_scan.sh <target_url> [output_file] [extra_args...]}"
OUTPUT="${2:-/tmp/nuclei_tor_results.txt}"
shift 2 || true
EXTRA_ARGS="$@"
TIMEOUT=300  # 5 minutes max

# Tor proxy from env var, with fallback default
TOR_PROXY="${PROMETHEUS_TOR_PROXY:-socks5://[IP_ADDRESS]:9050}"
ALLOW_DIRECT="${PROMETHEUS_ALLOW_DIRECT:-false}"

echo "=== Nuclei Tor Scan ==="
echo "Target: $TARGET"
echo "Output: $OUTPUT"
echo "Timeout: ${TIMEOUT}s"
echo "Proxy: $TOR_PROXY"
echo "Allow direct fallback: $ALLOW_DIRECT"
echo ""

# Verify Tor is running
echo "Checking Tor connectivity..."
if ! curl -s --socks5 "$(echo $TOR_PROXY | sed 's/socks5:\/\///')" https://check.torproject.org/api/ip --max-time 15 | grep -q "true"; then
    if [ "$ALLOW_DIRECT" = "true" ]; then
        echo "Tor not available, but --allow-direct is set. Proceeding without Tor."
        TOR_PROXY=""
    else
        echo "ERROR: Tor is not running or not responding at $TOR_PROXY"
        echo "SCAN_FAILED: Tor not available" > "$OUTPUT"
        exit 1
    fi
fi
if [ -n "$TOR_PROXY" ]; then
    echo "Tor is running."
fi

# Pre-flight: check if target is reachable
echo ""
echo "Pre-flight: probing target..."
PROXY_CURL=""
if [ -n "$TOR_PROXY" ]; then
    PROXY_CURL="--socks5 $(echo $TOR_PROXY | sed 's/socks5:\/\///')"
fi

HTTP_CODE=$(curl -s $PROXY_CURL \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/[IP_ADDRESS] Safari/537.36" \
    -o /dev/null -w "%{http_code}" \
    --connect-timeout 10 --max-time 15 "$TARGET" 2>/dev/null || echo "000")

SERVER_HEADER=$(curl -sI $PROXY_CURL \
    -A "Mozilla/5.0" \
    --connect-timeout 10 --max-time 15 "$TARGET" 2>/dev/null | grep -i "^server:" | head -1 || echo "")

echo "HTTP status: $HTTP_CODE  Server: $SERVER_HEADER"

WAF_DETECTED=false
if echo "$SERVER_HEADER" | grep -qiE "akamai|cloudflare|cloudfront|fastly"; then
    WAF_DETECTED=true
    echo "WARNING: CDN/WAF detected ($SERVER_HEADER). Nuclei findings will be limited."
    echo "Many templates will return WAF block pages, not real vulnerabilities."
fi

if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "000" ]; then
    echo "WARNING: Target returning $HTTP_CODE — likely blocked by WAF."
fi

# Build exclusion list for WAF-triggering template paths
EXCLUDE_DIRS=()
if $WAF_DETECTED; then
    EXCLUDE_DIRS+=(
        "-exclude-templates" "technologies/"
        "-exclude-templates" "exposed-panels/"
        "-exclude-templates" "exposed-cnvd/"
        "-exclude-templates" "takeovers/"
    )
fi

# Run nuclei
echo ""
echo "Starting nuclei scan (timeout: ${TIMEOUT}s, WAF mode: $WAF_DETECTED)..."
echo ""

# JSON output file for structured results
JSON_OUTPUT="${OUTPUT%.*}.json"

# Build proxy args for nuclei
NUC_PROXY_ARGS=()
if [ -n "$TOR_PROXY" ]; then
    NUC_PROXY_ARGS=("-proxy" "$TOR_PROXY")
fi

# Try nuclei through Tor first
set +e
timeout $TIMEOUT nuclei \
    -u "$TARGET" \
    "${NUC_PROXY_ARGS[@]}" \
    -severity high,critical \
    -timeout 15 \
    -retries 1 \
    -no-interactsh \
    -no-httpx \
    -rate-limit 5 \
    -c 10 \
    -silent \
    -json \
    -o "$JSON_OUTPUT" \
    "${EXCLUDE_DIRS[@]}" \
    $EXTRA_ARGS \
    2>&1 | tee "$OUTPUT"

EXIT_CODE=${PIPESTATUS[0]}
set -e

# If Tor failed and --allow-direct is set, retry without proxy
if [ $EXIT_CODE -ne 0 ] && [ $EXIT_CODE -ne 124 ] && [ "$ALLOW_DIRECT" = "true" ] && [ -n "$TOR_PROXY" ]; then
    echo ""
    echo "Tor scan failed (exit $EXIT_CODE). Retrying directly per --allow-direct..."
    timeout $TIMEOUT nuclei \
        -u "$TARGET" \
        -severity high,critical \
        -timeout 15 \
        -retries 1 \
        -no-interactsh \
        -no-httpx \
        -rate-limit 5 \
        -c 10 \
        -silent \
        -json \
        -o "$JSON_OUTPUT" \
        "${EXCLUDE_DIRS[@]}" \
        $EXTRA_ARGS \
        2>&1 | tee "$OUTPUT"
    EXIT_CODE=${PIPESTATUS[0]}
    echo "Direct fallback done (exit $EXIT_CODE)."
fi

# Generate human-readable summary from JSON output
FINDING_COUNT=0
WAF_NOISE=0
REAL_FINDINGS=0
if [ -f "$JSON_OUTPUT" ] && [ -s "$JSON_OUTPUT" ]; then
    FINDING_COUNT=$(wc -l < "$JSON_OUTPUT")
    WAF_NOISE=$(grep -ci '"matched".*[Aa]kamai\|\"matched\".*[Ww][Aa][Ff]\|\"info\".*\"name\".*[Bb]lock\|\"info\".*\"name\".*403\|\"info\".*\"name\".*[Ff]orbidden' "$JSON_OUTPUT" 2>/dev/null || echo 0)
    REAL_FINDINGS=$((FINDING_COUNT - WAF_NOISE))
fi

echo ""
echo "=== Scan Results ==="
echo "Total findings: $FINDING_COUNT"
echo "Likely WAF noise: $WAF_NOISE"
echo "Likely real findings: $REAL_FINDINGS"
if [ $REAL_FINDINGS -gt 0 ]; then
    echo ""
    echo "Real findings (filtered):"
    grep -v 'akamai\|blocked\|403\|forbidden' "$JSON_OUTPUT" 2>/dev/null | head -20 || true
fi

echo ""
if [ $EXIT_CODE -eq 124 ]; then
    echo "SCAN_TIMEOUT: Nuclei scan timed out after ${TIMEOUT}s" >> "$OUTPUT"
    echo "Scan TIMED OUT after ${TIMEOUT}s"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "Scan completed successfully."
else
    echo "Scan completed with exit code $EXIT_CODE"
fi

echo "SCAN_COMPLETE: exit=$EXIT_CODE findings=$FINDING_COUNT real=$REAL_FINDINGS json=$JSON_OUTPUT"
