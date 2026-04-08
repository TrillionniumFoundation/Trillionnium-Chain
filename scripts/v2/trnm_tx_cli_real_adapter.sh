#!/usr/bin/env bash
set -euo pipefail

# Real tx CLI adapter (env-driven, chain-specific).
# Interface is fixed for worker strict gates:
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
  tx wait <tx_hash> [--timeout <sec>] [--interval <sec>]
  tx transfer --from <name> --to <address> --amount <n> [--denom <denom>] [--store <path>]

Env:
  TRNM_TX_BIN, TRNM_RPC, TRNM_CHAIN_ID, TRNM_KEY_NAME, TRNM_KEYRING_BACKEND
  TRNM_GAS, TRNM_GAS_ADJUSTMENT, TRNM_FEES, TRNM_BROADCAST_MODE
  TRNM_TX_COMMIT_CMD, TRNM_TX_REVEAL_CMD, TRNM_TX_QUERY_CMD
  TRNM_TX_WRAPPER_DELEGATE_BIN, TRNM_TX_WRAPPER_CLI
EOF
}

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

extract_tx_hash() {
  local out="$1"
  # JSON: {"txhash":"..."} and common aliases used by tx/query tooling.
  local h
  h=$(printf "%s" "$out" | sed -n 's/.*"txhash"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*"tx_hash"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  fi
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*"txHash"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  fi
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*"transaction_hash"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  fi
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*"transactionHash"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
  fi
  if [[ -n "$h" ]]; then
    printf "%s" "$h"
    return 0
  fi
  # text: txhash: XXXXX and common aliases.
  h=$(printf "%s" "$out" | sed -n 's/.*txhash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,\}\).*/\1/p' | head -n1 || true)
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*tx_hash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,\}\).*/\1/p' | head -n1 || true)
  fi
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*txHash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,\}\).*/\1/p' | head -n1 || true)
  fi
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*transaction_hash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,\}\).*/\1/p' | head -n1 || true)
  fi
  if [[ -z "$h" ]]; then
    h=$(printf "%s" "$out" | sed -n 's/.*transactionHash[[:space:]]*[:=][[:space:]]*\([0-9A-Fa-f]\{16,\}\).*/\1/p' | head -n1 || true)
  fi
  if [[ -n "$h" ]]; then
    printf "%s" "$h"
    return 0
  fi
  return 1
}

normalize_status() {
  local raw="$1"
  local cleaned canonical
  cleaned=$(printf "%s" "$raw" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/^[[:space:]"'"'"'`]+//; s/[[:space:]"'"'"'`[:punct:]]+$//')
  canonical=$(printf "%s" "$cleaned" | sed -E 's/[^[:alnum:]]+/_/g; s/^_+//; s/_+$//')

  case "$canonical" in
    pending|submitted|accepted|queued|broadcast|broadcasted|broadcasting|processing|executing|in_progress|inflight|in_flight)
      printf "pending"
      ;;
    committed|confirmed|success|succeeded|ok|included|finalized|finalised|finalising|finalizing|complete|completed|done)
      printf "committed"
      ;;
    fail|failed|error|rejected|reverted|aborted|dropped|timeout|timed_out|expired)
      printf "fail"
      ;;
    *)
      printf "%s" "$cleaned"
      ;;
  esac
}

normalize_tx_hash() {
  local raw="$1"
  local cleaned
  cleaned=$(printf "%s" "$raw" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/^[[:space:]"'"'"'`({\[]+//; s/[[:space:]"'"'"'`,;:)}\]]+$//')

  if [[ "$cleaned" =~ ^0x[0-9a-f]+$ ]]; then
    printf "%s" "$cleaned"
    return 0
  fi
  if [[ "$cleaned" =~ ^[0-9a-f]{6,}$ ]]; then
    printf "%s" "$cleaned"
    return 0
  fi
  return 1
}

infer_status_from_code() {
  local out="$1"
  local code=""

  code=$(printf "%s" "$out" | sed -n 's/.*"code"[[:space:]]*:[[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}.*/\1/p' | head -n1 || true)
  if [[ -z "$code" ]]; then
    code=$(printf "%s" "$out" | sed -n 's/.*\b\(deliver_tx_code\|check_tx_code\|tx_code\|code\)[[:space:]]*[:=][[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}.*/\2/p' | head -n1 || true)
  fi

  if [[ -z "$code" ]]; then
    return 1
  fi

  if [[ "$code" == "0" ]]; then
    printf "committed"
  else
    printf "fail"
  fi
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
  wait|transfer)
    delegate_to_cli "${@:3}"
    ;;
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

    seen_hash=$(extract_tx_hash "$out" || true)
    if [[ -n "$seen_hash" ]]; then
      normalized_seen_hash=$(normalize_tx_hash "$seen_hash" || true)
      normalized_requested_hash=$(normalize_tx_hash "$tx_hash" || true)
      if [[ -n "$normalized_seen_hash" && -n "$normalized_requested_hash" && "$normalized_seen_hash" != "$normalized_requested_hash" ]]; then
        echo "tx query response hash mismatch: requested=$normalized_requested_hash got=$normalized_seen_hash" >&2
        exit 1
      fi
    fi

    status=$(printf "%s" "$out" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"tx_status"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"txStatus"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"transaction_status"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"transactionStatus"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"state"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"tx_state"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"txState"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"transaction_state"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*"transactionState"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*\([Tt][Xx]_\|[Tt][Rr][Aa][Nn][Ss][Aa][Cc][Tt][Ii][Oo][Nn]_\)\?[Ss][Tt][Aa][Tt][Uu][Ss][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\2/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*[Tt][Xx][Ss][Tt][Aa][Tt][Uu][Ss][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*[Tt][Rr][Aa][Nn][Ss][Aa][Cc][Tt][Ii][Oo][Nn][Ss][Tt][Aa][Tt][Uu][Ss][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*\([Tt][Xx]_\|[Tt][Rr][Aa][Nn][Ss][Aa][Cc][Tt][Ii][Oo][Nn]_\)\?[Ss][Tt][Aa][Tt][Ee][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\2/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*[Tt][Xx][Ss][Tt][Aa][Tt][Ee][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      status=$(printf "%s" "$out" | sed -n 's/.*[Tt][Rr][Aa][Nn][Ss][Aa][Cc][Tt][Ii][Oo][Nn][Ss][Tt][Aa][Tt][Ee][[:space:]]*[:=][[:space:]]*\([^[:space:]}\",]\+\).*/\1/p' | head -n1 || true)
    fi
    if [[ -z "$status" ]]; then
      scalar_status=$(printf "%s" "$out" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    value = json.loads(raw)
except Exception:
    raise SystemExit(0)
payload = value.get("result", value) if isinstance(value, dict) else value
primary = payload
if isinstance(payload, dict):
    response = payload.get("response") if isinstance(payload.get("response"), dict) else None
    nested = (
        payload.get("tx_response")
        or payload.get("txResponse")
        or (response.get("tx_response") if response else None)
        or (response.get("txResponse") if response else None)
        or (response.get("data") if response and isinstance(response.get("data"), dict) else None)
        or (payload.get("responseData") if isinstance(payload.get("responseData"), dict) else None)
    )
    if isinstance(nested, dict):
        primary = nested
for container in [primary, payload]:
    if not isinstance(container, dict):
        continue
    for key in ["status", "tx_status", "txStatus", "transaction_status", "transactionStatus", "state", "tx_state", "txState", "transaction_state", "transactionState"]:
        if key not in container:
            continue
        field = container[key]
        if isinstance(field, bool):
            print("committed" if field else "fail")
            raise SystemExit(0)
        if isinstance(field, int):
            print("committed" if field == 0 else "fail")
            raise SystemExit(0)
        if isinstance(field, str):
            print(field)
            raise SystemExit(0)
raise SystemExit(0)
' || true)
      if [[ -n "$scalar_status" ]]; then
        status="$scalar_status"
      fi
    fi
    if [[ -z "$status" ]]; then
      status=$(infer_status_from_code "$out" || true)
    else
      status="$(normalize_status "$status")"
    fi
    if [[ -z "$status" ]]; then
      status="unknown"
    fi

    echo "tx_hash=${seen_hash:-$tx_hash}"
    echo "status=$status"
    ;;
  *)
    echo "unknown tx subcommand: $sub" >&2
    exit 2
    ;;
esac
