#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="$ROOT/run"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/bft-round-change-$TS.log"
REPORT="$OUT_DIR/bft-round-change-$TS.txt"
mkdir -p "$OUT_DIR"

WAL_DIR="$OUT_DIR/consensus-wal-roundchange-$TS"

cargo run -q -p trnm-node -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 4 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --validators 4 \
  --byzantine 1 \
  --bft-max-rounds 3 \
  --bft-fault-rounds 2 \
  --bft-wal-dir "$WAL_DIR" >"$LOG" 2>&1

grep -q '^\[bft\].*step=RoundChange' "$LOG"
grep -q '^\[bft\].*step=Commit' "$LOG"
grep -q '^\[consensus\].*bft_round_change_total=' "$LOG"

a=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_round_change_total=\([0-9]*\).*/\1/p' | tail -n1)
b=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_committed_heights=\([0-9]*\).*/\1/p' | tail -n1)

if [[ -z "$a" || -z "$b" ]]; then
  echo "[FAIL] failed to parse consensus summary" >&2
  exit 2
fi

if [[ "$a" -le 0 ]]; then
  echo "[FAIL] expected bft_round_change_total > 0, got $a" >&2
  exit 3
fi

if [[ "$b" -le 0 ]]; then
  echo "[FAIL] expected bft_committed_heights > 0, got $b" >&2
  exit 4
fi

{
  echo "log=$LOG"
  echo "bft_round_change_total=$a"
  echo "bft_committed_heights=$b"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] bft round-change passed: $REPORT"