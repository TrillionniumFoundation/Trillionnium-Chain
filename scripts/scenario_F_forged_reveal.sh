#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
KEYRING="${KEYRING:-test}"
CREATOR_KEY="${CREATOR_KEY:-bob}"
WORKER_KEY="${WORKER_KEY:-alice}"
TASK_PATH="${TASK_PATH:-$ROOT/tasks/example_futures}"
RESULT_HASH="${RESULT_HASH:-good-result-hash}"
RESULT_URI="${RESULT_URI:-ipfs://result-good}"
COMMIT_SALT="${COMMIT_SALT:-commit-salt}"
FORGED_SALT="${FORGED_SALT:-forged-salt}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

tx_ok() {
  local out rc tries=0
  while (( tries < 8 )); do
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    if [[ $rc -eq 0 ]] && { grep -q '"code":0' <<<"${out// /}" || grep -q 'code: 0' <<<"$out"; }; then
      return 0
    fi
    if grep -qi "account sequence mismatch" <<<"$out"; then
      ((tries++)); sleep 0.8; continue
    fi
    echo "$out"
    return 1
  done
  echo "$out"
  return 1
}

workload_stats() {
  "$BIN" query workload list-task -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c 'import json,sys;o=json.load(sys.stdin);ids=[int(t.get("id",0)) for t in o.get("Task",[]) if str(t.get("id","0")).isdigit()];total=int(o.get("pagination",{}).get("total",0));print(f"{max(ids) if ids else 0} {total}")'
}
latest_task_id() { workload_stats | awk '{print $1}'; }
latest_task_total() { workload_stats | awk '{print $2}'; }

commit_hash() {
  local task_id="$1" result_hash="$2" salt="$3" worker_addr="$4"
  python3 - <<PY
import hashlib
print(hashlib.sha256(f"{int('$task_id')}|{'$result_hash'}|{'$salt'}|{'$worker_addr'}".encode()).hexdigest())
PY
}

ensure_worker_registered() {
  local worker_addr
  worker_addr="$($BIN keys show "$WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
  if $BIN query workload show-worker "$worker_addr" --node "$NODE" --home "$HOME_DIR" >/dev/null 2>&1; then
    return 0
  fi
  set +e
  REG_OUT="$($BIN tx workload register-worker "$WORKER_KEY" "ipfs://worker-$WORKER_KEY" \
    --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
  REG_RC=$?
  set -e
  if [[ $REG_RC -eq 0 ]] && { grep -q '"code":0' <<<"${REG_OUT// /}" || grep -q 'code: 0' <<<"$REG_OUT"; }; then
    return 0
  fi
  if grep -Eqi 'insufficient funds|spendable balance' <<<"$REG_OUT"; then
    echo "⚠️ SKIPPED: worker registration requires more stake/funds than available"
    exit 0
  fi
  echo "$REG_OUT"
  return 1
}

log "Scenario F: forged reveal must be rejected"
before=$(latest_task_id)
before_total=$(latest_task_total)

tx_ok "$BIN" tx workload create-task "$TASK_PATH" 0 0 "" "" \
  --from "$CREATOR_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5

sleep 1
id="$before"
after_total="$before_total"
for _ in {1..8}; do
  id=$(latest_task_id || echo "$before")
  after_total=$(latest_task_total || echo "$before_total")
  if [[ "$id" -gt "$before" || "$after_total" -gt "$before_total" ]]; then break; fi
  sleep 0.8
done
if [[ "$id" -le "$before" ]]; then id=$((before+1)); fi

ensure_worker_registered

tx_ok "$BIN" tx workload accept-task "$id" \
  --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5

worker_addr="$($BIN keys show "$WORKER_KEY" -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
ch="$(commit_hash "$id" "$RESULT_HASH" "$COMMIT_SALT" "$worker_addr")"

tx_ok "$BIN" tx workload commit-result "$id" "$ch" \
  --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5

log "Submit forged reveal (salt mismatch)"
set +e
OUT="$($BIN tx workload reveal-result "$id" "$RESULT_HASH" "$RESULT_URI" "$FORGED_SALT" \
  --from "$WORKER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5 2>&1)"
RC=$?
set -e

echo "$OUT" | sed -n '1,120p'
if [[ $RC -eq 0 ]] && { grep -q '"code":0' <<<"${OUT// /}" || grep -q 'code: 0' <<<"$OUT"; }; then
  echo "❌ forged reveal unexpectedly succeeded"
  exit 1
fi

echo "✅ Scenario F passed: forged reveal rejected"
