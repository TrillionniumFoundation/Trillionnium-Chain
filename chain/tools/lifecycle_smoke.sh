#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./tools/lifecycle_smoke.sh [CHAIN_ID] [FROM] [NODE]

CHAIN_ID="${1:-chain}"
FROM="${2:-alice}"
NODE="${3:-http://127.0.0.1:26657}"
BIN="${BIN:-chaind}"
FEES="${FEES:-200stake}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
MAX_WAIT_BLOCKS="${MAX_WAIT_BLOCKS:-300}"

wait_tx() {
  local txhash="$1"
  for _ in {1..30}; do
    if "$BIN" q tx "$txhash" --node "$NODE" -o json >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "[ERR] tx not found in time: $txhash" >&2
  return 1
}

latest_height() {
  "$BIN" status --node "$NODE" 2>/dev/null | jq -r '.SyncInfo.latest_block_height | tonumber'
}

expect_event_attr() {
  local txhash="$1"
  local event_type="$2"
  local key="$3"
  local expected="$4"

  local got
  got="$("$BIN" q tx "$txhash" --node "$NODE" -o json | jq -r --arg et "$event_type" --arg k "$key" '
    .events[] | select(.type == $et) | .attributes[] | select(.key == $k) | .value
  ' | tail -n1)"

  if [[ "$got" != "$expected" ]]; then
    echo "[ERR] event validation failed for tx=$txhash event=$event_type key=$key expected=$expected got=${got:-<empty>}" >&2
    return 1
  fi

  echo "  event_ok: $event_type.$key=$expected"
}

wait_for_release_height() {
  local release_height="$1"
  local current
  local waited=0

  current="$(latest_height)"
  while (( current < release_height )); do
    if (( waited >= MAX_WAIT_BLOCKS )); then
      echo "[ERR] cooldown wait timeout: current=$current release=$release_height waited_blocks=$waited" >&2
      return 1
    fi

    local remaining=$(( release_height - current ))
    echo "  waiting cooldown... current=$current target=$release_height remaining=$remaining"
    sleep "$SLEEP_SECONDS"

    local next
    next="$(latest_height)"
    if (( next > current )); then
      waited=$(( waited + (next - current) ))
    fi
    current="$next"
  done

  echo "  cooldown reached at height=$current (target=$release_height)"
}

WORKER_ADDR="$($BIN keys show "$FROM" -a)"

echo "[1/6] register-worker"
TX_REGISTER="$($BIN tx workload register-worker \
  --node-id smoke-node \
  --ipfs-addr /ip4/127.0.0.1/tcp/4001 \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes -o json | jq -r '.txhash')"
wait_tx "$TX_REGISTER"
echo "  tx_register=$TX_REGISTER"
expect_event_attr "$TX_REGISTER" "workload_register_worker" "worker" "$WORKER_ADDR"

echo "[2/6] request-unbonding"
TX_REQ="$($BIN tx workload request-unbonding \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes -o json | jq -r '.txhash')"
wait_tx "$TX_REQ"
echo "  tx_request_unbonding=$TX_REQ"
expect_event_attr "$TX_REQ" "workload_request_unbonding" "worker" "$WORKER_ADDR"

AMOUNT="$("$BIN" q tx "$TX_REQ" --node "$NODE" -o json | jq -r '
  .events[] | select(.type=="workload_request_unbonding") | .attributes[] | select(.key=="amount") | .value
' | tail -n1)"
RELEASE_HEIGHT="$("$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json | jq -r '.unbonding.releaseHeight | tonumber')"

echo "[3/6] query unbonding"
"$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json

echo "[4/6] wait cooldown until release height"
wait_for_release_height "$RELEASE_HEIGHT"

echo "[5/6] finalize-unbonding"
TX_FINALIZE="$($BIN tx workload finalize-unbonding \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes -o json | jq -r '.txhash')"
wait_tx "$TX_FINALIZE"
echo "  tx_finalize_unbonding=$TX_FINALIZE"
expect_event_attr "$TX_FINALIZE" "workload_finalize_unbonding" "worker" "$WORKER_ADDR"
expect_event_attr "$TX_FINALIZE" "workload_finalize_unbonding" "amount" "$AMOUNT"

echo "[6/6] verify unbonding removed"
if "$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json >/dev/null 2>&1; then
  echo "[ERR] unbonding still exists after finalize" >&2
  exit 1
fi

echo "OK: lifecycle smoke completed with cooldown wait + finalize + event checks."
