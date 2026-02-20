#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/ecosystem-alpha/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"
cat > "$OUT_DIR/alpha-checklist.txt" <<EOF
sdk_status=prepared
examples_status=3_required_pending
external_dev_runs=0
EOF
echo "[OK] $OUT_DIR/alpha-checklist.txt"
