#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"
RPC_PORT="${TRNM_COMETBFT_RPC_PORT:-27657}"
P2P_PORT="${TRNM_COMETBFT_P2P_PORT:-27656}"
ABCI_PORT="${TRNM_COMETBFT_ABCI_PORT:-27658}"
KEEP="${TRNM_COMETBFT_SPIKE_KEEP:-0}"
CLEAN_ON_SUCCESS="${TRNM_COMETBFT_SPIKE_CLEAN_ON_SUCCESS:-}"
APP_PID=""
COMET_PID=""
ROOT_CREATED_BY_SCRIPT=0
ROOT_MARKER_NAME=".trnm-comet-spike-root-v1"
ROOT_MARKER_VALUE="trnm-comet-spike-root-v1"

if [[ -n "${TRNM_COMETBFT_SPIKE_ROOT:-}" ]]; then
  ROOT="$TRNM_COMETBFT_SPIKE_ROOT"
  if [[ ! -e "$ROOT" ]]; then
    mkdir -p -- "$ROOT"
    ROOT_CREATED_BY_SCRIPT=1
  elif [[ ! -d "$ROOT" ]]; then
    printf 'TRNM_COMETBFT_SINGLE_NODE_FAILED reason=root_is_not_directory root=%s\n' \
      "$ROOT" >&2
    exit 2
  fi
  CLEAN_ON_SUCCESS="${CLEAN_ON_SUCCESS:-0}"
else
  ROOT="$(mktemp -d /tmp/trnm-comet-spike.XXXXXX)"
  ROOT_CREATED_BY_SCRIPT=1
  CLEAN_ON_SUCCESS="${CLEAN_ON_SUCCESS:-1}"
fi

if [[ "$ROOT_CREATED_BY_SCRIPT" == "1" ]]; then
  printf '%s\n' "$ROOT_MARKER_VALUE" >"$ROOT/$ROOT_MARKER_NAME"
fi

safe_to_remove_root() {
  local base
  [[ "$ROOT_CREATED_BY_SCRIPT" == "1" ]] || return 1
  [[ -d "$ROOT" && ! -L "$ROOT" ]] || return 1
  [[ -f "$ROOT/$ROOT_MARKER_NAME" && ! -L "$ROOT/$ROOT_MARKER_NAME" ]] || return 1
  [[ "$(cat "$ROOT/$ROOT_MARKER_NAME")" == "$ROOT_MARKER_VALUE" ]] || return 1
  base="$(basename -- "$ROOT")"
  [[ "$base" == trnm-comet-spike.* || "$base" == trnm-comet-spike-* ]]
}

terminate_pids() {
  local pid
  local live=()
  for pid in "$@"; do
    [[ -z "$pid" ]] || live+=("$pid")
  done
  ((${#live[@]} > 0)) || return 0
  for pid in "${live[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in "${live[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
  for pid in "${live[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
}

cleanup() {
  local status=$?
  trap - EXIT
  terminate_pids "$COMET_PID" "$APP_PID"
  if [[ "$status" == "0" && "$KEEP" != "1" && "$CLEAN_ON_SUCCESS" == "1" ]]; then
    if safe_to_remove_root; then
      rm -rf -- "$ROOT"
    else
      printf 'TRNM_COMETBFT_ROOT_PRESERVED reason=cleanup_safety_check_failed root=%s\n' \
        "$ROOT" >&2
    fi
  else
    printf 'TRNM_COMETBFT_ROOT_PRESERVED status=%s root=%s\n' "$status" "$ROOT" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'printf "TRNM_COMETBFT_SINGLE_NODE_FAILED line=%s root=%s\n" "$LINENO" "$ROOT" >&2' ERR

command -v "$COMETBFT_BIN" >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
command -v base64 >/dev/null
command -v python3 >/dev/null

mkdir -p "$ROOT"
APP_BIN="${TRNM_COMETBFT_APP_BIN:-}"
CLI_BIN="${TRNM_COMETBFT_CLI_BIN:-}"
if [[ -z "$APP_BIN" ]]; then
  cargo build -q -p trnm-consensus-app --bin trnm-cometbft-app
  APP_BIN="$PWD/target/debug/trnm-cometbft-app"
fi
if [[ -z "$CLI_BIN" ]]; then
  cargo build -q -p trnm-node --bin trnm-chain-cli
  CLI_BIN="$PWD/target/debug/trnm-chain-cli"
fi
test -x "$APP_BIN"
test -x "$CLI_BIN"

key_json="$("$CLI_BIN" keygen --output "$ROOT/operator.key")"
public_key="$(printf '%s' "$key_json" | jq -r .public_key_hex)"
jq -n \
  --arg public_key "$public_key" \
  --arg state_path "$ROOT/app-state.json" \
  '{
    schema:"trnm_cometbft_app_config_v1",
    chain_id:"trnm-comet-spike",
    authorized_signers:[{
      signer_id:"did:operator:1",
      signer_role:"operator",
      public_key_hex:$public_key
    }],
    state_path:$state_path
  }' > "$ROOT/app.json"

for nonce in 1 2; do
  jq -n \
    --arg sender did:operator:1 \
    --arg account "fixture:single:$nonce" \
    --argjson nonce "$nonce" \
    '{schema:"trnm_canonical_tx_v1",sender:$sender,nonce:$nonce,max_gas:100000,fee_limit:"100000",command:{type:"credit_account",account:$account,amount:"1"}}' \
    >"$ROOT/payload-$nonce.bin"
  "$CLI_BIN" sign \
    --private-key "$ROOT/operator.key" \
    --chain-id trnm-comet-spike \
    --command-id "command-comet-$nonce" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$nonce" \
    --payload-type trnm.canonical.tx.v1 \
    --payload-file "$ROOT/payload-$nonce.bin" \
    --output "$ROOT/tx-$nonce.json" >/dev/null
done

"$COMETBFT_BIN" init --home "$ROOT/comet" >/dev/null
initial_validators="$(python3 - "$ROOT/comet/config/genesis.json" <<'PY'
import base64
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    validators = json.load(handle)["validators"]
result = [
    {
        "public_key_hex": base64.b64decode(validator["pub_key"]["value"]).hex(),
        "voting_power": int(validator["power"]),
    }
    for validator in validators
]
result.sort(key=lambda validator: validator["public_key_hex"])
print(json.dumps(result, separators=(",", ":")))
PY
)"
jq --arg public_key "$public_key" --argjson initial_validators "$initial_validators" \
  '.chain_id="trnm-comet-spike"
   | .consensus_params.version.app="3"
   | .app_state={
       schema:"trnm_cometbft_genesis_v2",
       chain_id:"trnm-comet-spike",
       app_version:3,
       authorized_signers:[{
         signer_id:"did:operator:1",
         signer_role:"operator",
         public_key_hex:$public_key
       }],
       validator_governance:{
         schema:"trnm_validator_governance_v1",
         signer_id:"did:operator:1",
         min_activation_delay_blocks:2,
         unsafe_allow_single_validator_genesis:true
       },
       initial_validators:$initial_validators
     }' \
  "$ROOT/comet/config/genesis.json" > "$ROOT/genesis.json"
mv "$ROOT/genesis.json" "$ROOT/comet/config/genesis.json"

start_app() {
  "$APP_BIN" \
    --config "$ROOT/app.json" \
    --listen-addr "127.0.0.1:$ABCI_PORT" \
    >"$ROOT/app.log" 2>&1 &
  APP_PID=$!
}

start_comet() {
  "$COMETBFT_BIN" start \
    --home "$ROOT/comet" \
    --proxy_app "tcp://127.0.0.1:$ABCI_PORT" \
    --rpc.laddr "tcp://127.0.0.1:$RPC_PORT" \
    --p2p.laddr "tcp://127.0.0.1:$P2P_PORT" \
    --consensus.create_empty_blocks=false \
    >"$ROOT/comet.log" 2>&1 &
  COMET_PID=$!
}

wait_rpc() {
  for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$RPC_PORT/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

broadcast_commit() {
  local tx_file="$1"
  local tx_b64
  tx_b64="$(base64 -w0 "$tx_file")"
  curl -fsS \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_commit\",\"params\":{\"tx\":\"$tx_b64\"}}" \
    "http://127.0.0.1:$RPC_PORT"
}

start_app
start_comet
wait_rpc

first="$(broadcast_commit "$ROOT/tx-1.json")"
test "$(printf '%s' "$first" | jq -r '.result.check_tx.code')" = "0"
test "$(printf '%s' "$first" | jq -r '.result.tx_result.code')" = "0"
test "$(printf '%s' "$first" | jq -r '.result.height')" = "1"

terminate_pids "$APP_PID"
APP_PID=""
for _ in $(seq 1 40); do
  if ! kill -0 "$COMET_PID" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
terminate_pids "$COMET_PID"
COMET_PID=""
start_app
start_comet
wait_rpc

second="$(broadcast_commit "$ROOT/tx-2.json")"
test "$(printf '%s' "$second" | jq -r '.result.check_tx.code')" = "0"
test "$(printf '%s' "$second" | jq -r '.result.tx_result.code')" = "0"
test "$(printf '%s' "$second" | jq -r '.result.height')" = "2"

block="$(curl -fsS "http://127.0.0.1:$RPC_PORT/block?height=2")"
test -n "$(printf '%s' "$block" | jq -r '.result.block.header.app_hash')"
test "$(printf '%s' "$block" | jq -r '.result.block.data.txs|length')" = "1"
test "$(jq -r .height "$ROOT/app-state.json")" = "2"

printf 'TRNM_COMETBFT_SINGLE_NODE_OK height=2 app_hash=%s root=%s\n' \
  "$(printf '%s' "$block" | jq -r '.result.block.header.app_hash')" \
  "$ROOT"
