#!/usr/bin/env bash
set -euo pipefail

# Real tx CLI adapter (env-driven, chain-specific).
# Interface is fixed for worker strict gates:
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

# Optional full command overrides (recommended when chain module path differs):
# - TRNM_TX_COMMIT_CMD
# - TRNM_TX_REVEAL_CMD
# - TRNM_TX_QUERY_CMD
# Placeholders supported: {task_id} {worker} {commit_hash} {nonce} {result_hash} {salt_hex} {tx_hash}

usage() {
  cat <<'EOF'
trnm real tx adapter

Usage:
  tx --help
  tx commit-result <task_id> <worker> <commit_hash> <nonce>
  tx reveal-result <task_id> <result_hash> <salt_hex>
  tx query <tx_hash>

Env:
  TRNM_TX_BIN, TRNM_RPC, TRNM_CHAIN_ID, TRNM_KEY_NAME, TRNM_KEYRING_BACKEND
  TRNM_GAS, TRNM_GAS_ADJUSTMENT, TRNM_FEES, TRNM_BROADCAST_MODE
  TRNM_TX_COMMIT_CMD, TRNM_TX_REVEAL_CMD, TRNM_TX_QUERY_CMD
EOF
}

extract_tx_hash() {
  local out="$1"
  # JSON: {"txhash":"..."}
  local h
  h=$(printf "%s" "$out" | sed -n 's/.*"txhash"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  if [[ -n "$h" ]]; then
    printf "%s" "$h"
    return 0
  fi
  # text: txhash: XXXXX
  h=$(printf "%s" "$out" | sed -n 's/.*txhash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,\}\).*/\1/p' | head -n1 || true)
  if [[ -n "$h" ]]; then
    printf "%s" "$h"
    return 0
  fi
  return 1
}

normalize_status() {
  local raw="$1"
  local cleaned
  cleaned=$(printf "%s" "$raw" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E "s/^[[:space:]\"'\0`]+//; s/[[:space:]\"'\0`[:punct:]]+$//")

  case "$cleaned" in
    pending|submitted|accepted|queued|broadcast|broadcasted)
      printf "pending"
      ;;
    committed|confirmed|success|succeeded|ok|included|finalized)
      printf "committed"
      ;;
    fail|failed|error|rejected|reverted|aborted|dropped|timeout|timed_out|timed-out|expired)
      printf "fail"
      ;;
    *)
      printf "%s" "$cleaned"
      ;;
  esac
}

run_cmd() {
  local cmd="$1"
  set +e
  local out
  out=$(bash -lc "$cmd" 2>&1)
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "$out" >&2
    return $rc
  fi
  local txh=""
  txh=$(extract_tx_hash "$out" || true)
  if [[ -z "$txh" ]]; then
    # if chain cli doesn't return txhash, still make deterministic surrogate for gate traceability
    txh=$(printf "%s" "$out" | shasum -a 256 | awk '{print $1}')
  fi
  echo "tx_hash=$txh"
}

if [[ "${1:-}" != "tx" ]]; then
  usage >&2
  exit 2
fi

sub="${2:-}"
if [[ "$sub" == "--help" || "$sub" == "-h" || -z "$sub" ]]; then
  usage
  exit 0
fi

case "$sub" in
  commit-result)
    if [[ "$#" -ne 6 ]]; then
      echo "invalid args for commit-result: expected 4 payload args" >&2
      exit 2
    fi
    task_id="${3:-}"; worker="${4:-}"; commit_hash="${5:-}"; nonce="${6:-}"
    [[ -n "$task_id" && -n "$worker" && -n "$commit_hash" && -n "$nonce" ]] || { echo "invalid args" >&2; exit 2; }

    if [[ -n "${TRNM_TX_COMMIT_CMD:-}" ]]; then
      cmd="$TRNM_TX_COMMIT_CMD"
      cmd="${cmd//\{task_id\}/$task_id}"
      cmd="${cmd//\{worker\}/$worker}"
      cmd="${cmd//\{commit_hash\}/$commit_hash}"
      cmd="${cmd//\{nonce\}/$nonce}"
    else
      cmd="$TX_BIN tx pouw commit-result $task_id $worker $commit_hash $nonce --from $KEY_NAME --keyring-backend $KEYRING --chain-id $CHAIN_ID --node $RPC --gas $GAS --gas-adjustment $GAS_ADJ --fees $FEES --broadcast-mode $BROADCAST_MODE -y"
    fi
    run_cmd "$cmd"
    ;;
  reveal-result)
    if [[ "$#" -ne 5 ]]; then
      echo "invalid args for reveal-result: expected 3 payload args" >&2
      exit 2
    fi
    task_id="${3:-}"; result_hash="${4:-}"; salt_hex="${5:-}"
    [[ -n "$task_id" && -n "$result_hash" && -n "$salt_hex" ]] || { echo "invalid args" >&2; exit 2; }

    if [[ -n "${TRNM_TX_REVEAL_CMD:-}" ]]; then
      cmd="$TRNM_TX_REVEAL_CMD"
      cmd="${cmd//\{task_id\}/$task_id}"
      cmd="${cmd//\{result_hash\}/$result_hash}"
      cmd="${cmd//\{salt_hex\}/$salt_hex}"
    else
      cmd="$TX_BIN tx pouw reveal-result $task_id $result_hash $salt_hex --from $KEY_NAME --keyring-backend $KEYRING --chain-id $CHAIN_ID --node $RPC --gas $GAS --gas-adjustment $GAS_ADJ --fees $FEES --broadcast-mode $BROADCAST_MODE -y"
    fi
    run_cmd "$cmd"
    ;;
  query)
    if [[ "$#" -ne 3 ]]; then
      echo "invalid args for query: expected tx_hash only" >&2
      exit 2
    fi
    tx_hash="${3:-}"
    [[ -n "$tx_hash" ]] || { echo "invalid args" >&2; exit 2; }

    if [[ -n "${TRNM_TX_QUERY_CMD:-}" ]]; then
      cmd="$TRNM_TX_QUERY_CMD"
      cmd="${cmd//\{tx_hash\}/$tx_hash}"
    else
      cmd="$TX_BIN query tx $tx_hash --node $RPC --output json"
    fi

    set +e
    out=$(bash -lc "$cmd" 2>&1)
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "$out" >&2
      exit $rc
    fi

    seen_hash=$(printf "%s" "$out" | sed -n 's/.*"txhash"[[:space:]]*:[[:space:]]*"\([0-9A-Fa-f]\{16,128\}\)".*/\1/p' | head -n1 || true)
    if [[ -z "$seen_hash" ]]; then
      seen_hash=$(printf "%s" "$out" | sed -n 's/.*tx_hash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,128\}\).*/\1/p' | head -n1 || true)
    fi
    status=$(printf "%s" "$out" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*\([Tt][Xx]_\)\?[Ss][Tt][Aa][Tt][Uu][Ss][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\2/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status="committed"
    else
      status="$(normalize_status "$status")"
    fi

    echo "tx_hash=${seen_hash:-$tx_hash}"
    echo "status=$status"
    ;;
  *)
    echo "unknown tx subcommand: $sub" >&2
    exit 2
    ;;
esac
