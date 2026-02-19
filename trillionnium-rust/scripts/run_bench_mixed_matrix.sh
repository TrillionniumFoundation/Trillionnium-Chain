#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
READ_FANOUT="${READ_FANOUT:-3}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/bench-mixed-matrix-$TS.txt"
mkdir -p "$OUT_DIR"

echo "bench_mixed_matrix txs=$TXS read_fanout=$READ_FANOUT" | tee "$OUT"
for KEYS in 5000 2000 1000 500 200 100; do
  for WRITE_EVERY in 1 2 4; do
    echo "--- keys=$KEYS write_every=$WRITE_EVERY ---" | tee -a "$OUT"
    cargo run -q -p trnm-bench -- \
      --workload mixed \
      --txs "$TXS" \
      --keys "$KEYS" \
      --read-fanout "$READ_FANOUT" \
      --write-every "$WRITE_EVERY" \
      --profile | tee -a "$OUT"
  done
done

echo "[OK] mixed matrix report: $OUT"
