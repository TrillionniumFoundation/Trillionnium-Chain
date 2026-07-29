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

cargo run -q -p trnm-node --features legacy-harness --bin trnm-sim -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 4 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --validators 4 \
  --byzantine 1 \
  --bft-max-rounds 4 \
  --bft-fault-rounds 2 \
  --bft-missed-proposal-threshold 1 \
  --bft-leader-penalty-rounds 2 \
  --bft-round-change-backoff-ms 5 \
  --bft-round-change-backoff-max-ms 20 \
  --bft-wal-dir "$WAL_DIR" >"$LOG" 2>&1

grep -q '^\[bft\].*step=RoundChange' "$LOG"
grep -q '^\[bft\].*step=RoundBackoff' "$LOG"
grep -q '^\[bft\].*step=Commit' "$LOG"
grep -q '^\[consensus\].*bft_round_change_total=' "$LOG"
grep -q '^\[consensus\].*bft_double_vote_total=' "$LOG"
grep -q '^\[consensus\].*bft_leader_missed_proposals=' "$LOG"

a=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_round_change_total=\([0-9]*\).*/\1/p' | tail -n1)
b=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_committed_heights=\([0-9]*\).*/\1/p' | tail -n1)
c=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_round_change_backoff_total_ms=\([0-9]*\).*/\1/p' | tail -n1)
d=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_double_vote_total=\([0-9]*\).*/\1/p' | tail -n1)

if [[ -z "$a" || -z "$b" || -z "$c" || -z "$d" ]]; then
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

if [[ "$c" -le 0 ]]; then
  echo "[FAIL] expected bft_round_change_backoff_total_ms > 0, got $c" >&2
  exit 5
fi

if [[ "$d" -lt 0 ]]; then
  echo "[FAIL] expected bft_double_vote_total >= 0, got $d" >&2
  exit 6
fi

{
  echo "log=$LOG"
  echo "bft_round_change_total=$a"
  echo "bft_committed_heights=$b"
  echo "bft_round_change_backoff_total_ms=$c"
  echo "bft_double_vote_total=$d"
  echo "note=thresholds: missed_threshold=1 penalty_rounds=2 backoff_ms=5 backoff_cap_ms=20"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] bft round-change passed: $REPORT"
