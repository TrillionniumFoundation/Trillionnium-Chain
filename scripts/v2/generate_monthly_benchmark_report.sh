#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/reports/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/monthly-benchmark-report.md"
latest_bench=$(ls -1t "$ROOT"/trillionnium/run/bench/* 2>/dev/null | head -n 1 || true)
latest_health=$(ls -1t "$ROOT"/trillionnium/run/health/* 2>/dev/null | head -n 1 || true)
cat > "$REPORT" <<EOF
# Trillionnium Monthly Benchmark Report (Auto)

- generated_at: $(date '+%F %T')
- latest_bench_artifact: ${latest_bench:-n/a}
- latest_health_artifact: ${latest_health:-n/a}

## Snapshot
- pipeline: auto-generated
- status: draft
EOF
echo "[OK] $REPORT"
