#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

OUT_DIR="run/challenges"
OUT="$OUT_DIR/relay-from-spoof-probe-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

# 该探针依赖 trnm-rpc relay 子命令可用
if ! cargo run -q -p trnm-rpc -- --help | grep -q "relay"; then
  echo "[FAIL] trnm-rpc relay command not available in this build" >&2
  exit 1
fi

session=$(cargo run -q -p trnm-rpc -- relay open --route "challenge.from.spoof" --source "probe" | sed -n 's/.*session=\([^ ]*\).*/\1/p' | head -n1)
if [[ -z "$session" ]]; then
  echo "[FAIL] cannot open relay session" >&2
  exit 1
fi

o1=$(cargo run -q -p trnm-rpc -- relay send --session "$session" --from "alice" --text "hello from alice" --source "probe" 2>&1 || true)
o2=$(cargo run -q -p trnm-rpc -- relay send --session "$session" --from "bob" --text "hello from bob" --source "probe" 2>&1 || true)

ok1=$(echo "$o1" | grep -c "status=accepted" || true)
ok2=$(echo "$o2" | grep -c "status=accepted" || true)

{
  echo "challenge=relay_from_spoof_probe"
  echo "session=$session"
  echo "alice_send_accepted=$ok1"
  echo "bob_send_accepted=$ok2"
  if [[ "$ok1" -gt 0 && "$ok2" -gt 0 ]]; then
    echo "result=IDENTITY_SPOOF_SURFACE_POSSIBLE"
  else
    echo "result=NOT_CONFIRMED"
  fi
} | tee "$OUT"

echo "[OK] report: $OUT"
