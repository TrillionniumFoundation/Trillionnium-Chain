#!/usr/bin/env bash
set -euo pipefail

# Demo: workload_denom governance-style update + lifecycle tx flow
# Assumptions:
# - local dev chain is running (ignite chain serve)
# - key "alice" exists in local keyring
# - chain-id is "chain"

CHAIN_ID="chain"
NODE="http://127.0.0.1:26657"
FROM="alice"
FEES="200stake"
YES="--yes"

BIN="chaind"

echo "[1/4] Query current workload params"
$BIN q workload params --node "$NODE" -o json

echo "[2/4] Update workload params: workload_denom=ufoo (authority message)"
AUTHORITY="$($BIN q auth module-account gov --node "$NODE" -o json | jq -r '.account.base_account.address')"

$BIN tx workload update-params \
  "$AUTHORITY" \
  '{"workloadDenom":"ufoo"}' \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  $YES

echo "[3/4] Query params again (expect ufoo)"
$BIN q workload params --node "$NODE" -o json

echo "[4/4] Create + complete a task (burn should use ufoo denom)"
$BIN tx workload create-task \
  --bounty 100 \
  --ipfs-hash "QmDemoHash" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  $YES

$BIN tx workload update-task \
  --id 0 \
  --status 2 \
  --result-hash "QmResultHash" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  $YES

echo "Done. Check tx events workload_update_task/workload_slash_worker for denom field = ufoo."
