#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

N="${N:-50}"
OUT_DIR="run/challenges"
OUT="$OUT_DIR/rpc-pending-pool-spam-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

ok=0
fail=0
malformed=0
last_hash=""

for i in $(seq 1 "$N"); do
  from="attacker_$i"
  to="sink_$i"
  amount="$((1000 + i))"
  nonce="$i"

  if out=$(cargo run -q -p trnm-rpc -- send-tx --from "$from" --to "$to" --amount "$amount" --nonce "$nonce" --signature "bad_sig_$i" 2>&1); then
    parsed=$(python3 -c 'import json,sys
s=sys.stdin.read().strip()
try:
    j=json.loads(s)
    print((j.get("tx_hash") or "")+"\t"+(j.get("status") or ""))
except Exception:
    print("\t")' <<< "$out")
    h="${parsed%%$'\t'*}"
    status="${parsed#*$'\t'}"
    [[ -n "$h" ]] && last_hash="$h"
    if [[ "$status" == "pending" && -n "$h" ]]; then
      ok=$((ok+1))
    else
      fail=$((fail+1))
      [[ -z "$h" ]] && malformed=$((malformed+1))
    fi
  else
    fail=$((fail+1))
  fi
done

{
  echo "challenge=rpc_pending_pool_spam"
  echo "submitted=$N"
  echo "pending_with_hash_count=$ok"
  echo "non_pending_or_errors=$fail"
  echo "malformed_or_missing_hash=$malformed"
  echo "last_tx_hash=${last_hash:-n/a}"
  if [[ "$ok" -gt 0 ]]; then
    echo "result=VULNERABLE_SURFACE_CONFIRMED"
  else
    echo "result=NOT_CONFIRMED"
  fi
} | tee "$OUT"

echo "[OK] report: $OUT"
