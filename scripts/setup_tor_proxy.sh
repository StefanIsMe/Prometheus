#!/usr/bin/env bash
# setup_tor_proxy.sh — Verify Tor SOCKS5 proxy availability for Prometheus Docker sandbox scans
set -euo pipefail

PASS=0
FAIL=0
WARN=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }

echo "=== Prometheus Tor Proxy Setup ==="
echo ""

# ── 1. Check if Tor is installed ──────────────────────────────────────────────
echo "[1/5] Checking Tor installation..."
if command -v tor &>/dev/null; then
    ok "Tor binary found: $(command -v tor)"
else
    fail "Tor is not installed. Install with: sudo apt install tor / brew install tor"
fi

# ── 2. Check if Tor service is running ────────────────────────────────────────
echo "[2/5] Checking Tor service status..."
if systemctl is-active --quiet tor 2>/dev/null; then
    ok "Tor service is active (systemd)"
elif pgrep -x tor &>/dev/null; then
    ok "Tor process is running (PID $(pgrep -x tor | head -1))"
else
    fail "Tor service is not running. Start with: sudo systemctl start tor"
fi

# ── 3. Verify SOCKS5 proxy on localhost ───────────────────────────────────────
echo "[3/5] Checking SOCKS5 proxy at 127.0.0.1:9050..."
if timeout 3 bash -c 'echo >/dev/tcp/127.0.0.1/9050' 2>/dev/null; then
    ok "SOCKS5 proxy reachable at 127.0.0.1:9050"
else
    fail "SOCKS5 proxy NOT reachable at 127.0.0.1:9050"
fi

# ── 4. Verify Docker bridge access (172.17.0.1) ──────────────────────────────
echo "[4/5] Checking Docker bridge access at 172.17.0.1:9050..."
if timeout 3 bash -c 'echo >/dev/tcp/172.17.0.1/9050' 2>/dev/null; then
    ok "SOCKS5 proxy reachable at 172.17.0.1:9050 (Docker bridge)"
else
    warn "SOCKS5 proxy NOT reachable at 172.17.0.1:9050 — containers may need --network host"
fi

# ── 5. Test Tor connectivity ──────────────────────────────────────────────────
echo "[5/5] Testing Tor connectivity via curl..."
if command -v curl &>/dev/null; then
    TOR_IP=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -oP '"IsTor":\s*\K\w+' || true)
    EXTERNAL_IP=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -oP '"IP":\s*"\K[^"]+' || true)

    if [[ "$TOR_IP" == "true" ]]; then
        ok "Tor connectivity confirmed (exit IP: ${EXTERNAL_IP:-unknown})"
    elif [[ -n "$EXTERNAL_IP" ]]; then
        warn "Proxy works but Tor flag not confirmed (IP: $EXTERNAL_IP)"
    else
        fail "Cannot reach internet through Tor proxy"
    fi
else
    warn "curl not found — skipping connectivity test"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
echo "  PASS: $PASS  FAIL: $FAIL  WARN: $WARN"
echo ""
echo "Docker proxy URL for Prometheus containers:"
echo "  socks5://host.docker.internal:9050"
echo "  socks5://172.17.0.1:9050"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "STATUS: FAIL — fix the issues above before running sandboxed scans."
    exit 1
else
    echo "STATUS: PASS — Tor proxy is ready for Prometheus."
    exit 0
fi
