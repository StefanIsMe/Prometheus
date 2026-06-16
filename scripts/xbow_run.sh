#!/usr/bin/env bash
# scripts/xbow_run.sh — convenience entry for the XBOW harness.
#
# Usage:
#   ./scripts/xbow_run.sh list
#   ./scripts/xbow_run.sh run --ids XBEN-001-24 --concurrency 1
#   ./scripts/xbow_run.sh run --concurrency 4
#   ./scripts/xbow_run.sh report <run_id>
#
# Requirements (all already required by Prometheus itself):
#   - docker (with `docker compose`)
#   - git
#   - python3 >= 3.11
#   - the prometheus-sandbox:local image is already pulled
#
# No new Python dependencies are installed by this script.
set -euo pipefail

# Resolve repo root from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Sanity checks.
if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required (not on PATH)" >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required (not on PATH)" >&2
  exit 1
fi

PYTHON_BIN="${PYTHON:-python3}"
PYTHONPATH="$REPO_ROOT" exec "$PYTHON_BIN" -m prometheus.interface.main xbow "$@"
