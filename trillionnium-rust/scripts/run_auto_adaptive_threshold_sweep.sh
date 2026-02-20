#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-10000}"
KEYS="${KEYS:-2000}"
READ_FANOUT="${READ_FANOUT:-4}"
WRITE_EVERY="${WRITE_EVERY:-2}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/auto-adaptive-threshold-sweep-$TS.txt"
mkdir -p "$OUT_DIR"

THRESHOLDS=(0.14 0.18 0.22 0.26 0.30)

echo "auto_adaptive_threshold_sweep" | tee "$OUT"
echo "txs=$TXS keys=$KEYS read_fanout=$READ_FANOUT write_every=$WRITE_EVERY" | tee -a "$OUT"

for t in "${THRESHOLDS[@]}"; do
  echo "--- threshold=$t strategy=auto-adaptive ---" | tee -a "$OUT"
  TRNM_AUTO_HOT_STREAK_RATIO="$t" cargo run -q -p trnm-bench -- \
    --workload mixed \
    --txs "$TXS" \
    --keys "$KEYS" \
    --read-fanout "$READ_FANOUT" \
    --write-every "$WRITE_EVERY" \
    --strategy auto-adaptive \
    --profile | tee -a "$OUT"
done

echo "[OK] auto-adaptive threshold sweep report: $OUT"
