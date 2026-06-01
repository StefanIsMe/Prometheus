#!/usr/bin/env bash
# prometheus-safe-launch.sh — Pre-flight checks + launch prometheus
# Ensures Tor is running on the host BEFORE prometheus starts,
# so the agent never wastes turns diagnosing host-level issues.
#
# Usage: ./prometheus-safe-launch.sh [all prometheus args passed through]
# Example: ./prometheus-safe-launch.sh -t https://example.com --rate-limit 5 -m deep

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

ERRORS=0

# --- 1. Check Tor is running ---
echo "=== Pre-flight checks ==="

if systemctl is-active --quiet tor 2>/dev/null; then
    log_ok "Tor service is active"
else
    log_warn "Tor service not active — attempting to start..."
    if sudo systemctl start tor 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet tor; then
            log_ok "Tor service started successfully"
        else
            log_fail "Tor service failed to start"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_fail "Cannot start Tor (sudo failed?)"
        ERRORS=$((ERRORS + 1))
    fi
fi

# --- 2. Check Tor SOCKS port is listening ---
if ss -tlnp | grep -q ':9050 '; then
    log_ok "Tor SOCKS5 proxy listening on port 9050"
else
    log_fail "Nothing listening on port 9050"
    ERRORS=$((ERRORS + 1))
fi

# --- 3. Check Tor proxy actually works (with retries) ---
TOR_OK=0
for attempt in 1 2 3; do
    RESULT=$(curl -s --max-time 15 --proxy socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null || true)
    if echo "$RESULT" | grep -q '"IsTor":true'; then
        TOR_IP=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['IP'])" 2>/dev/null || echo "unknown")
        log_ok "Tor proxy verified (exit IP: $TOR_IP)"
        TOR_OK=1
        break
    else
        if [ "$attempt" -lt 3 ]; then
            log_warn "Tor check attempt $attempt failed, retrying in 5s..."
            sleep 5
        fi
    fi
done

if [ "$TOR_OK" -eq 0 ]; then
    log_fail "Tor proxy not working after 3 attempts"
    ERRORS=$((ERRORS + 1))
fi

# --- 4. Check Docker is running ---
if docker ps >/dev/null 2>&1; then
    log_ok "Docker daemon is running"
else
    log_fail "Docker daemon not accessible"
    ERRORS=$((ERRORS + 1))
fi

# --- 5. Check sandbox image exists ---
if docker image inspect ghcr.io/useprometheus/prometheus-sandbox:0.1.13 >/dev/null 2>&1; then
    log_ok "prometheus sandbox image present"
else
    log_warn "prometheus sandbox image not found (will pull on first run — ~15GB)"
fi

# --- 6. Check prometheus source exists ---
prometheus_SOURCE="$HOME/prometheus-source"
if [ -f "$prometheus_SOURCE/run_prometheus.py" ]; then
    log_ok "prometheus source at $prometheus_SOURCE"
else
    log_fail "prometheus source not found at $prometheus_SOURCE"
    ERRORS=$((ERRORS + 1))
fi

# --- 7. Check prometheus config ---
if [ -f "$HOME/.prometheus/cli-config.json" ]; then
    log_ok "prometheus config exists"
else
    log_warn "No prometheus config at ~/.prometheus/cli-config.json"
fi

echo ""

# --- Abort if any critical checks failed ---
if [ "$ERRORS" -gt 0 ]; then
    echo -e "${RED}=== $ERRORS pre-flight check(s) FAILED. Aborting. ===${NC}"
    if [ "$TOR_OK" -eq 0 ]; then
        echo ""
        echo "To fix Tor:"
        echo "  sudo systemctl restart tor"
        echo "  sleep 10"
        echo "  curl -s --proxy socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip"
    fi
    exit 1
fi

echo -e "${GREEN}=== All pre-flight checks passed. Launching prometheus. ===${NC}"
echo ""

# --- Launch prometheus from source ---
cd "$prometheus_SOURCE"
exec python3 run_prometheus.py "$@"
