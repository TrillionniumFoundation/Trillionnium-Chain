#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-20000}"
KEYS="${KEYS:-2000}"
READ_FANOUT="${READ_FANOUT:-3}"
WRITE_EVERY="${WRITE_EVERY:-2}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/aggressive-deepscan-ab-hotstreak-$TS.txt"
mkdir -p "$OUT_DIR"

echo "aggressive_deepscan_ab_hotstreak" | tee "$OUT"
echo "workload=hot-streak txs=$TXS keys=$KEYS read_fanout=$READ_FANOUT write_every=$WRITE_EVERY" | tee -a "$OUT"

echo "--- strategy=original ---" | tee -a "$OUT"
cargo run -q -p trnm-bench -- \
  --workload hot-streak \
  --txs "$TXS" \
  --keys "$KEYS" \
  --read-fanout "$READ_FANOUT" \
  --write-every "$WRITE_EVERY" \
  --strategy original \
  --profile | tee -a "$OUT"

echo "--- strategy=aggressive-greedy (default) ---" | tee -a "$OUT"
cargo run -q -p trnm-bench -- \
  --workload hot-streak \
  --txs "$TXS" \
  --keys "$KEYS" \
  --read-fanout "$READ_FANOUT" \
  --write-every "$WRITE_EVERY" \
  --strategy aggressive-greedy \
  --profile | tee -a "$OUT"

echo "--- strategy=aggressive-greedy (TRNM_AGGR_DEEP_SCAN=1) ---" | tee -a "$OUT"
TRNM_AGGR_DEEP_SCAN=1 cargo run -q -p trnm-bench -- \
  --workload hot-streak \
  --txs "$TXS" \
  --keys "$KEYS" \
  --read-fanout "$READ_FANOUT" \
  --write-every "$WRITE_EVERY" \
  --strategy aggressive-greedy \
  --profile | tee -a "$OUT"

echo "[OK] deepscan A/B report: $OUT"
