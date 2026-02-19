#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/bench-strategy-compare-$TS.txt"
mkdir -p "$OUT_DIR"

echo "bench_strategy_compare txs=$TXS" | tee "$OUT"
for STRATEGY in original footprint-desc write-first write-last hot-bucket-interleave; do
  echo "=== strategy=$STRATEGY ===" | tee -a "$OUT"
  for KEYS in 5000 2000 1000 500 200 100; do
    echo "--- keys=$KEYS ---" | tee -a "$OUT"
    cargo run -q -p trnm-bench -- \
      --workload mixed \
      --txs "$TXS" \
      --keys "$KEYS" \
      --read-fanout 3 \
      --write-every 1 \
      --strategy "$STRATEGY" \
      --profile | tee -a "$OUT"
  done
done

echo "[OK] strategy compare report: $OUT"
