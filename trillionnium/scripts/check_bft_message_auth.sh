#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="$ROOT/run"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$OUT_DIR/bft-message-auth-$TS.log"
REPORT="$OUT_DIR/bft-message-auth-$TS.txt"
mkdir -p "$OUT_DIR"

cargo run -q -p trnm-node --bin trnm-sim -- \
  --config configs/node1.toml \
  --block-ms 5 \
  --max-blocks 3 \
  --demo-tasks 6 \
  --demo-keys 3 \
  --validators 4 \
  --byzantine 1 \
  --bft-max-rounds 3 \
  --bft-fault-rounds 1 >"$LOG" 2>&1

grep -q '^\[bft-net\] reject reason=bad_sig' "$LOG"
grep -q '^\[bft-net\] reject reason=replay' "$LOG"
grep -q '^\[bft-net\] reject reason=stale_nonce' "$LOG"

grep -q '^\[consensus\].*bft_auth_reject_bad_sig_total=' "$LOG"

auth_bad=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_auth_reject_bad_sig_total=\([0-9]*\).*/\1/p' | tail -n1)
auth_replay=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_auth_reject_replay_total=\([0-9]*\).*/\1/p' | tail -n1)
auth_stale=$(grep '^\[consensus\]' "$LOG" | sed -n 's/.*bft_auth_reject_stale_nonce_total=\([0-9]*\).*/\1/p' | tail -n1)

for metric in auth_bad auth_replay auth_stale; do
  value="${!metric:-}"
  if [[ -z "$value" || ! "$value" =~ ^[0-9]+$ || "$value" -le 0 ]]; then
    echo "[FAIL] expected ${metric} > 0, got '${value:-<empty>}' (log=$LOG)" >&2
    exit 1
  fi
done

{
  echo "log=$LOG"
  echo "auth_reject_bad_sig_total=${auth_bad:-0}"
  echo "auth_reject_replay_total=${auth_replay:-0}"
  echo "auth_reject_stale_nonce_total=${auth_stale:-0}"
  echo "status=PASS"
} > "$REPORT"

echo "[OK] bft message auth passed: $REPORT"
