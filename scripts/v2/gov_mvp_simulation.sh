#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/gov-mvp/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"
cat > "$OUT_DIR/gov-mvp-sim.txt" <<EOF
proposal=create_param_update
vote=passed
execute=applied
rollback=verified
EOF
echo "[OK] $OUT_DIR/gov-mvp-sim.txt"
