#!/usr/bin/env bash
set -euo pipefail

BIN="$(go env GOPATH)/bin/chaind"
HOME_DIR="${HOME}/.chain"
CHAIN_ID="chain"
BOUNTY="500"
FEE="500stake"
RPC="http://localhost:26657"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing command: $1" >&2; exit 1; }
}

need_cmd jq
[ -x "$BIN" ] || { echo "[ERR] chaind not found at $BIN" >&2; exit 1; }

echo "[1/7] Reset chain state"
"$BIN" tendermint unsafe-reset-all --home "$HOME_DIR" >/dev/null

ALICE_ADDR="$($BIN keys show alice -a --keyring-backend test --home "$HOME_DIR")"
BOB_ADDR="$($BIN keys show bob -a --keyring-backend test --home "$HOME_DIR")"

echo "[2/7] Start node"
"$BIN" start --home "$HOME_DIR" >/tmp/trnm-smoke-node.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  if curl -sf "$RPC/status" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf "$RPC/status" >/dev/null || { echo "[ERR] node not ready" >&2; exit 1; }

for _ in $(seq 1 30); do
  height_before="$(curl -s "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
  if [ "${height_before}" -gt 0 ] 2>/dev/null; then
    break
  fi
  sleep 1
done
[ "${height_before:-0}" -gt 0 ] || { echo "[ERR] chain did not produce first block" >&2; exit 1; }
echo "    node height: $height_before"

alice_before="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
bob_before="$($BIN query bank balances "$BOB_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"

echo "[3/7] Create task"
IPFS_HASH="ipfs://smoke-$(date +%s)"
"$BIN" tx workload create-task "$IPFS_HASH" "$BOUNTY" 0 none none \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-create.json

sleep 2

task_total="$($BIN query workload list-task --home "$HOME_DIR" -o json | jq -r '.pagination.total')"
[ "$task_total" -gt 0 ] || { echo "[ERR] task not created" >&2; exit 1; }
TASK_ID=$((task_total - 1))

echo "    created task id: $TASK_ID"

alice_after_create="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
expected_after_create=$((alice_before - BOUNTY))
[ "$alice_after_create" -eq "$expected_after_create" ] || {
  echo "[ERR] alice balance mismatch after create: got=$alice_after_create expected=$expected_after_create" >&2
  exit 1
}

echo "[4/7] Complete task"
"$BIN" tx workload update-task "$IPFS_HASH" "$BOUNTY" 2 none result://ok \
  --id "$TASK_ID" --from bob --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-update.json

sleep 2

echo "[5/7] Validate task state"
task_json="$($BIN query workload show-task "$TASK_ID" --home "$HOME_DIR" -o json)"
status="$(echo "$task_json" | jq -r '.Task.status')"
worker="$(echo "$task_json" | jq -r '.Task.worker')"
result_hash="$(echo "$task_json" | jq -r '.Task.resultHash')"

[ "$status" = "2" ] || { echo "[ERR] status is $status (expected 2)" >&2; exit 1; }
[ "$worker" = "$BOB_ADDR" ] || { echo "[ERR] worker is $worker (expected $BOB_ADDR)" >&2; exit 1; }
[ "$result_hash" = "result://ok" ] || { echo "[ERR] resultHash is $result_hash" >&2; exit 1; }

echo "[6/7] Validate balances/escrow"
alice_after="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
bob_after="$($BIN query bank balances "$BOB_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
module_addr="$($BIN query auth module-account workload --home "$HOME_DIR" -o json | jq -r '.account.value.address')"
module_utrnm="$($BIN query bank balances "$module_addr" --home "$HOME_DIR" -o json | jq -r '([.balances[] | select(.denom=="utrnm") | .amount][0] // "0")')"

[ "$alice_after" -eq "$expected_after_create" ] || { echo "[ERR] alice final utrnm mismatch" >&2; exit 1; }
[ "$bob_after" -eq "$bob_before" ] || { echo "[ERR] bob utrnm changed unexpectedly" >&2; exit 1; }
[ "$module_utrnm" = "0" ] || { echo "[ERR] module escrow not empty: $module_utrnm" >&2; exit 1; }

echo "[7/7] PASS"
echo "    task_id=$TASK_ID status=$status"
echo "    alice: $alice_before -> $alice_after"
echo "    bob:   $bob_before -> $bob_after"
echo "    module(workload): utrnm=$module_utrnm"
echo "    node log: /tmp/trnm-smoke-node.log"
