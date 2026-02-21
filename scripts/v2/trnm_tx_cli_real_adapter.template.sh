#!/usr/bin/env bash
set -euo pipefail

# Real tx CLI adapter template.
# Keep this interface stable for worker gates:
#   $0 tx --help
#   $0 tx commit-result <task_id> <worker> <commit_hash> <nonce>
#   $0 tx reveal-result <task_id> <result_hash> <salt_hex>

RPC="${TRNM_RPC:-http://127.0.0.1:26657}"
CHAIN_ID="${TRNM_CHAIN_ID:-trnm-localnet}"
KEY_NAME="${TRNM_KEY_NAME:-worker1}"
KEYRING="${TRNM_KEYRING_BACKEND:-test}"
GAS="${TRNM_GAS:-auto}"
GAS_ADJ="${TRNM_GAS_ADJUSTMENT:-1.5}"
FEES="${TRNM_FEES:-1000utrnm}"
BROADCAST_MODE="${TRNM_BROADCAST_MODE:-sync}"
TX_BIN="${TRNM_TX_BIN:-chaind}"

if [[ "${1:-}" != "tx" ]]; then
  echo "usage: $0 tx <commit-result|reveal-result|--help> ..." >&2
  exit 2
fi

case "${2:-}" in
  --help|-h|"")
    cat <<'EOF'
Real tx adapter template

Usage:
  tx commit-result <task_id> <worker> <commit_hash> <nonce>
  tx reveal-result <task_id> <result_hash> <salt_hex>

Required env (example):
  TRNM_TX_BIN=chaind
  TRNM_CHAIN_ID=trnm-localnet
  TRNM_KEY_NAME=worker1
  TRNM_RPC=http://127.0.0.1:26657
EOF
    exit 0
    ;;
  commit-result)
    task_id="${3:-}"; worker="${4:-}"; commit_hash="${5:-}"; nonce="${6:-}"
    [[ -n "$task_id" && -n "$worker" && -n "$commit_hash" && -n "$nonce" ]] || { echo "invalid args" >&2; exit 2; }

    # TODO: replace module/msg path below with your chain's real tx command.
    # Example placeholder:
    # out="$($TX_BIN tx pouw commit-result "$task_id" "$worker" "$commit_hash" "$nonce" \
    #   --from "$KEY_NAME" --keyring-backend "$KEYRING" --chain-id "$CHAIN_ID" \
    #   --node "$RPC" --gas "$GAS" --gas-adjustment "$GAS_ADJ" --fees "$FEES" \
    #   --broadcast-mode "$BROADCAST_MODE" -y 2>&1)"

    out="simulated commit tx"
    tx_hash=$(printf "%s|%s|%s|%s|%s" "$task_id" "$worker" "$commit_hash" "$nonce" "$out" | shasum -a 256 | awk '{print $1}')
    echo "tx_hash=$tx_hash"
    ;;
  reveal-result)
    task_id="${3:-}"; result_hash="${4:-}"; salt_hex="${5:-}"
    [[ -n "$task_id" && -n "$result_hash" && -n "$salt_hex" ]] || { echo "invalid args" >&2; exit 2; }

    # TODO: replace module/msg path below with your chain's real tx command.
    # out="$($TX_BIN tx pouw reveal-result "$task_id" "$result_hash" "$salt_hex" ... 2>&1)"

    out="simulated reveal tx"
    tx_hash=$(printf "%s|%s|%s|%s" "$task_id" "$result_hash" "$salt_hex" "$out" | shasum -a 256 | awk '{print $1}')
    echo "tx_hash=$tx_hash"
    ;;
  *)
    echo "unknown subcommand: ${2:-}" >&2
    exit 2
    ;;
esac
