#!/usr/bin/env bash
set -euo pipefail

# Demo: workload_denom governance-style update + lifecycle tx flow
#
# Usage:
#   ./tools/demo_denom_governance_flow.sh [CHAIN_ID] [FROM] [NODE] [DENOM]
# Example:
#   ./tools/demo_denom_governance_flow.sh chain alice http://127.0.0.1:26657 ufoo

CHAIN_ID="${1:-chain}"
FROM="${2:-alice}"
NODE="${3:-http://127.0.0.1:26657}"
DENOM="${4:-ufoo}"
FEES="${FEES:-200stake}"
BIN="${BIN:-chaind}"

wait_tx() {
  local txhash="$1"
  for _ in {1..30}; do
    if $BIN q tx "$txhash" --node "$NODE" -o json >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "[ERR] tx not found in time: $txhash" >&2
  return 1
}

echo "[1/5] Query current workload params"
$BIN q workload params --node "$NODE" -o json

echo "[2/5] Update workload params: workload_denom=${DENOM}"
AUTHORITY="$($BIN q auth module-account gov --node "$NODE" -o json | jq -r '.account.base_account.address')"

TX_UPDATE_PARAMS="$($BIN tx workload update-params \
  "$AUTHORITY" \
  "{\"workloadDenom\":\"${DENOM}\"}" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes \
  -o json | jq -r '.txhash')"

wait_tx "$TX_UPDATE_PARAMS"
echo "  tx_update_params=$TX_UPDATE_PARAMS"

echo "[3/5] Query params again (expect ${DENOM})"
$BIN q workload params --node "$NODE" -o json

echo "[4/5] Create + complete a task (burn should use ${DENOM})"
TX_CREATE="$($BIN tx workload create-task \
  --bounty 100 \
  --ipfs-hash "QmDemoHash" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes \
  -o json | jq -r '.txhash')"
wait_tx "$TX_CREATE"
echo "  tx_create=$TX_CREATE"

TX_UPDATE_TASK="$($BIN tx workload update-task \
  --id 0 \
  --status 2 \
  --result-hash "QmResultHash" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes \
  -o json | jq -r '.txhash')"
wait_tx "$TX_UPDATE_TASK"
echo "  tx_update_task=$TX_UPDATE_TASK"

echo "[5/5] Verify events denom=${DENOM}"
$BIN q tx "$TX_UPDATE_TASK" --node "$NODE" -o json | \
  jq -r --arg d "$DENOM" '
    .events[] | select(.type=="workload_update_task") |
    .attributes[] | select(.key=="denom") | .value
  ' | grep -x "$DENOM" >/dev/null

echo "OK: workload_update_task event denom verified (${DENOM})."
