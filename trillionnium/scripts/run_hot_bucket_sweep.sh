#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TXS="${TXS:-10000}"
KEYS="${KEYS:-256}"
READ_FANOUT="${READ_FANOUT:-4}"
WRITE_EVERY="${WRITE_EVERY:-1}"
OUT_DIR="${OUT_DIR:-$ROOT/run/bench}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/hot-bucket-sweep-$TS.txt"
mkdir -p "$OUT_DIR"

BUCKETS_LIST=(8 12 16)

echo "hot_bucket_sweep" | tee "$OUT"
echo "workload=hot-streak txs=$TXS keys=$KEYS read_fanout=$READ_FANOUT write_every=$WRITE_EVERY" | tee -a "$OUT"

for b in "${BUCKETS_LIST[@]}"; do
  echo "--- buckets=$b strategy=hot-bucket-interleave ---" | tee -a "$OUT"
  TRNM_HOT_BUCKETS="$b" cargo run -q -p trnm-bench -- \
    --workload hot-streak \
    --txs "$TXS" \
    --keys "$KEYS" \
    --read-fanout "$READ_FANOUT" \
    --write-every "$WRITE_EVERY" \
    --strategy hot-bucket-interleave \
    --profile | tee -a "$OUT"
done

echo "--- baseline strategy=original ---" | tee -a "$OUT"
cargo run -q -p trnm-bench -- \
  --workload hot-streak \
  --txs "$TXS" \
  --keys "$KEYS" \
  --read-fanout "$READ_FANOUT" \
  --write-every "$WRITE_EVERY" \
  --strategy original \
  --profile | tee -a "$OUT"

echo "[OK] hot bucket sweep report: $OUT"
