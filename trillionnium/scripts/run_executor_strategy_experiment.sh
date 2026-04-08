#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
KEYS="${KEYS:-2000}"
READ_FANOUT="${READ_FANOUT:-4}"
WRITE_EVERY="${WRITE_EVERY:-2}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/executor-strategy-exp-$TS.txt"
mkdir -p "$OUT_DIR"

strategies=(original hot-bucket-interleave auto-adaptive aggressive-greedy)

echo "executor_strategy_experiment" | tee "$OUT"
echo "workload=mixed" | tee -a "$OUT"
echo "txs=$TXS keys=$KEYS read_fanout=$READ_FANOUT write_every=$WRITE_EVERY" | tee -a "$OUT"

for s in "${strategies[@]}"; do
  echo "--- strategy=$s ---" | tee -a "$OUT"
  cargo run -q -p trnm-bench -- \
    --workload mixed \
    --txs "$TXS" \
    --keys "$KEYS" \
    --read-fanout "$READ_FANOUT" \
    --write-every "$WRITE_EVERY" \
    --strategy "$s" \
    --profile | tee -a "$OUT"
done

echo "[OK] strategy experiment report: $OUT"
