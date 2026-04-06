#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

OUT_DIR="run/challenges"
OUT="$OUT_DIR/relay-source-quota-bypass-probe-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

N="${N:-40}"

if ! cargo run -q -p trnm-rpc -- --help | grep -q "relay"; then
  echo "[FAIL] trnm-rpc relay command not available in this build" >&2
  exit 1
fi

session=$(cargo run -q -p trnm-rpc -- relay open --route "challenge.quota.bypass" --source "quota-probe" | sed -n 's/.*session=\([^ ]*\).*/\1/p' | head -n1)
if [[ -z "$session" ]]; then
  echo "[FAIL] cannot open relay session" >&2
  exit 1
fi

accepted=0
rejected=0
for i in $(seq 1 "$N"); do
  src="src-$i"
  out=$(cargo run -q -p trnm-rpc -- relay send --session "$session" --from "attacker" --text "msg-$i" --source "$src" 2>&1 || true)
  if echo "$out" | grep -q "status=accepted"; then
    accepted=$((accepted+1))
  else
    rejected=$((rejected+1))
  fi
done

{
  echo "challenge=relay_source_quota_bypass_probe"
  echo "session=$session"
  echo "attempts=$N"
  echo "accepted=$accepted"
  echo "rejected=$rejected"
  if [[ "$accepted" -ge $((N*8/10)) ]]; then
    echo "result=BYPASS_LIKELY"
  else
    echo "result=NOT_CONFIRMED"
  fi
} | tee "$OUT"

echo "[OK] report: $OUT"
