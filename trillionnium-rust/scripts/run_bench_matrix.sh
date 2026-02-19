#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/bench-matrix-$TS.txt"
mkdir -p "$OUT_DIR"

echo "bench_matrix txs=$TXS" | tee "$OUT"
for KEYS in 20000 10000 5000 2000 1000 500 200 100 50 20 10; do
  echo "--- keys=$KEYS ---" | tee -a "$OUT"
  cargo run -q -p trnm-bench -- --txs "$TXS" --keys "$KEYS" --profile | tee -a "$OUT"
done

echo "[OK] matrix report: $OUT"
