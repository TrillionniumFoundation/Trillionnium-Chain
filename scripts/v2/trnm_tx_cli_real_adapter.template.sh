#!/usr/bin/env bash
set -euo pipefail

# Real tx CLI adapter template.
# Keep this interface stable for worker gates:
#   $0 tx --help
#   $0 tx commit-result <task_id> <worker> <commit_hash> <nonce>
#   $0 tx reveal-result <task_id> <result_hash> <salt_hex>
#   $0 tx query <tx_hash>
#   $0 tx wait <tx_hash> [--timeout <sec>] [--interval <sec>]
#   $0 tx transfer --from <name> --to <address> --amount <n> [--denom <denom>] [--store <path>]

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
  echo "usage: $0 tx <commit-result|reveal-result|query|wait|transfer|--help> ..." >&2
  exit 2
fi

resolve_delegate_bin() {
  local candidate="${TRNM_TX_WRAPPER_DELEGATE_BIN:-${TRNM_TX_WRAPPER_CLI:-trnm-cli}}"
  if command -v "$candidate" >/dev/null 2>&1; then
    command -v "$candidate"
    return 0
  fi

  local root
  root="$(cd "$(dirname "$0")/../.." && pwd)"
  local cargo_bin="$root/trillionnium/target/debug/trnm-cli"
  if [[ "$candidate" == "trnm-cli" && -x "$cargo_bin" ]]; then
    printf "%s\n" "$cargo_bin"
    return 0
  fi

  return 1
}

delegate_to_cli() {
  local delegate_bin
  if ! delegate_bin="$(resolve_delegate_bin)"; then
    echo "delegated tx subcommand requires trnm-cli (set TRNM_TX_WRAPPER_DELEGATE_BIN if needed)" >&2
    exit 127
  fi
  exec "$delegate_bin" tx "$@"
}

case "${2:-}" in
  --help|-h|"")
    cat <<'EOF'
Real tx adapter template

Usage:
  tx commit-result <task_id> <worker> <commit_hash> <nonce>
  tx reveal-result <task_id> <result_hash> <salt_hex>
  tx query <tx_hash>
  tx wait <tx_hash> [--timeout <sec>] [--interval <sec>]
  tx transfer --from <name> --to <address> --amount <n> [--denom <denom>] [--store <path>]

Required env (example):
  TRNM_TX_BIN=chaind
  TRNM_CHAIN_ID=trnm-localnet
  TRNM_KEY_NAME=worker1
  TRNM_RPC=http://127.0.0.1:26657
EOF
    exit 0
    ;;
  wait|transfer)
    delegate_to_cli "${@:3}"
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
  query)
    tx_hash="${3:-}"
    [[ -n "$tx_hash" ]] || { echo "invalid args" >&2; exit 2; }

    # TODO: replace this placeholder query with your chain's real tx query command.
    # Example placeholder:
    # out="$($TX_BIN query tx "$tx_hash" --node "$RPC" --output json 2>&1)"
    # status=$(printf "%s" "$out" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1)
    # IMPORTANT: do not default to status=committed when the chain response omits lifecycle
    # state entirely. Prefer deriving from explicit code/status fields, otherwise emit
    # status=unknown so readiness checks fail closed instead of reporting a false READY.

    echo "tx_hash=$tx_hash"
    echo "status=unknown"
    ;;
  *)
    echo "unknown subcommand: ${2:-}" >&2
    exit 2
    ;;
esac
