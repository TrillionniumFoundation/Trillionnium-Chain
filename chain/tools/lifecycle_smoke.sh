#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./tools/lifecycle_smoke.sh [CHAIN_ID] [FROM] [NODE]

CHAIN_ID="${1:-chain}"
FROM="${2:-alice}"
NODE="${3:-http://127.0.0.1:26657}"
BIN="${BIN:-chaind}"
FEES="${FEES:-200stake}"

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

echo "[1/4] register-worker"
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

echo "[2/4] request-unbonding"
TX_REQ="$($BIN tx workload request-unbonding \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes -o json | jq -r '.txhash')"
wait_tx "$TX_REQ"
echo "  tx_request_unbonding=$TX_REQ"

echo "[3/4] query unbonding"
$BIN q workload show-unbonding "$($BIN keys show "$FROM" -a)" --node "$NODE" -o json

echo "[4/4] done (finalize-unbonding requires cooldown blocks)"
