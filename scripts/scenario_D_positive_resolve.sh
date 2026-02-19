#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
KEYRING="${KEYRING:-test}"
RESOLVER_KEY="${RESOLVER_KEY:-bob}"  # dev local resolver (challenger)
TASK_ID="${TASK_ID:-}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

tx_ok() {
  local out rc tries=0
  while (( tries < 8 )); do
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    if [[ $rc -eq 0 ]] && { grep -q '"code":0' <<<"${out// /}" || grep -q 'code: 0' <<<"$out"; }; then
      echo "$out" | sed -n '1,80p' >&2
      txhash=$(echo "$out" | sed -n 's/.*txhash[:"] *\([A-Fa-f0-9]\{20,\}\).*/\1/p' | head -n 1)
      [[ -n "${txhash:-}" ]] && echo "$txhash"
      return 0
    fi
    if grep -qi "account sequence mismatch" <<<"$out"; then
      ((tries++)); sleep 0.8; continue
    fi
    echo "$out" >&2
    return 1
  done
  echo "$out" >&2
  return 1
}

if [[ -z "$TASK_ID" ]]; then
  TASK_ID="$($BIN query workload list-task -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);ids=[int(t.get("id",0)) for t in o.get("Task",[]) if str(t.get("status","0"))=="4" and str(t.get("id","0")).isdigit()];print(max(ids) if ids else 0)')"
fi

if [[ "$TASK_ID" -le 0 ]]; then
  echo "SKIP: no challenged task found (status=4). Run scenario_C_challenge.sh first."
  exit 0
fi

worker_addr="$($BIN keys show alice -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
stake_before="$($BIN query workload show-worker "$worker_addr" -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);w=o.get("worker") or o.get("Worker") or {}; print(int(w.get("stake",0)))')"

slash_percent="$($BIN query workload params -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);print(int(o.get("params",{}).get("worker_slash_percent_on_bad_result",20)))')"

log "Scenario D+ resolving challenged task_id=$TASK_ID via local dev resolver ($RESOLVER_KEY)"
TXH=$(tx_ok "$BIN" tx workload resolve-challenge "$TASK_ID" true "badresult123" "dev resolve" \
  --from "$RESOLVER_KEY" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
  --node "$NODE" --home "$HOME_DIR" --yes --gas auto --gas-adjustment 1.5)

if [[ -n "${TXH:-}" ]]; then
  for _ in {1..20}; do
    if "$BIN" query tx "$TXH" --node "$NODE" --home "$HOME_DIR" -o json >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
fi

expected_after=$(( stake_before - (stake_before * slash_percent / 100) ))
task_status=0
stake_after="$stake_before"
for _ in {1..24}; do
  task_status="$($BIN query workload show-task "$TASK_ID" -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);t=o.get("task") or o.get("Task") or {}; print(int(t.get("status",0)))')"
  stake_after="$($BIN query workload show-worker "$worker_addr" -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);w=o.get("worker") or o.get("Worker") or {}; print(int(w.get("stake",0)))')"
  if [[ "$task_status" -eq 6 && "$stake_after" -eq "$expected_after" ]]; then
    break
  fi
  sleep 0.8
done

echo "task_status=$task_status (expect 6=SLASHED)"
echo "stake_before=$stake_before stake_after=$stake_after expected_after=$expected_after slash_percent=$slash_percent"

if [[ "$task_status" -ne 6 ]]; then
  echo "❌ resolve path failed: expected task status 6"
  exit 1
fi
if [[ "$stake_after" -ne "$expected_after" ]]; then
  echo "❌ slash amount mismatch"
  exit 1
fi

echo "✅ Scenario D positive path passed: challenge resolved + worker slashed"
