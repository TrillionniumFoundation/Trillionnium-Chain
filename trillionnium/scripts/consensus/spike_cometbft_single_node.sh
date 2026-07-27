#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"
RPC_PORT="${TRNM_COMETBFT_RPC_PORT:-27657}"
P2P_PORT="${TRNM_COMETBFT_P2P_PORT:-27656}"
ABCI_PORT="${TRNM_COMETBFT_ABCI_PORT:-27658}"
ROOT="${TRNM_COMETBFT_SPIKE_ROOT:-$(mktemp -d /tmp/trnm-comet-spike.XXXXXX)}"
KEEP="${TRNM_COMETBFT_SPIKE_KEEP:-0}"
APP_PID=""
COMET_PID=""

cleanup() {
  test -z "$COMET_PID" || kill "$COMET_PID" 2>/dev/null || true
  test -z "$APP_PID" || kill "$APP_PID" 2>/dev/null || true
  test -z "$COMET_PID" || wait "$COMET_PID" 2>/dev/null || true
  test -z "$APP_PID" || wait "$APP_PID" 2>/dev/null || true
  if [[ "$KEEP" != "1" ]]; then
    rm -rf "$ROOT"
  fi
}
trap cleanup EXIT

command -v "$COMETBFT_BIN" >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
command -v base64 >/dev/null

mkdir -p "$ROOT"
key_json="$(cargo run -q -p trnm-node --bin trnm-chain-cli -- keygen --output "$ROOT/operator.key")"
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

printf 'deterministic-cometbft-payload-1' > "$ROOT/payload-1.bin"
printf 'deterministic-cometbft-payload-2' > "$ROOT/payload-2.bin"
for nonce in 1 2; do
  cargo run -q -p trnm-node --bin trnm-chain-cli -- sign \
    --private-key "$ROOT/operator.key" \
    --chain-id trnm-comet-spike \
    --command-id "command-comet-$nonce" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$nonce" \
    --payload-type opaque_fixture_v1 \
    --payload-file "$ROOT/payload-$nonce.bin" \
    --output "$ROOT/tx-$nonce.json" >/dev/null
done

"$COMETBFT_BIN" init --home "$ROOT/comet" >/dev/null
jq --arg public_key "$public_key" \
  '.chain_id="trnm-comet-spike"
   | .consensus_params.version.app="2"
   | .app_state={
       schema:"trnm_cometbft_genesis_v1",
       chain_id:"trnm-comet-spike",
       app_version:2,
       authorized_signers:[{
         signer_id:"did:operator:1",
         signer_role:"operator",
         public_key_hex:$public_key
       }]
     }' \
  "$ROOT/comet/config/genesis.json" > "$ROOT/genesis.json"
mv "$ROOT/genesis.json" "$ROOT/comet/config/genesis.json"

start_app() {
  cargo run -q -p trnm-consensus-app --bin trnm-cometbft-app -- \
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

kill "$APP_PID"
wait "$APP_PID" 2>/dev/null || true
APP_PID=""
for _ in $(seq 1 40); do
  if ! kill -0 "$COMET_PID" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
if kill -0 "$COMET_PID" 2>/dev/null; then
  kill "$COMET_PID"
fi
wait "$COMET_PID" 2>/dev/null || true
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
