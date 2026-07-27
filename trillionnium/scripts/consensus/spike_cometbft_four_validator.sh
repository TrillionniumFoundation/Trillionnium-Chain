#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"
ROOT="${TRNM_COMETBFT_SPIKE_ROOT:-$(mktemp -d /tmp/trnm-comet-four.XXXXXX)}"
KEEP="${TRNM_COMETBFT_SPIKE_KEEP:-0}"
BASE_RPC="${TRNM_COMETBFT_BASE_RPC_PORT:-28657}"
BASE_P2P="${TRNM_COMETBFT_BASE_P2P_PORT:-28656}"
BASE_ABCI="${TRNM_COMETBFT_BASE_ABCI_PORT:-28658}"
APP_PIDS=("" "" "" "")
COMET_PIDS=("" "" "" "")

cleanup() {
  for pid in "${COMET_PIDS[@]}" "${APP_PIDS[@]}"; do
    test -z "$pid" || kill "$pid" 2>/dev/null || true
  done
  for pid in "${COMET_PIDS[@]}" "${APP_PIDS[@]}"; do
    test -z "$pid" || wait "$pid" 2>/dev/null || true
  done
  if [[ "$KEEP" != "1" ]]; then
    rm -rf "$ROOT"
  fi
}
trap cleanup EXIT

command -v "$COMETBFT_BIN" >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
command -v base64 >/dev/null

cargo build -q -p trnm-consensus-app --bin trnm-cometbft-app
cargo build -q -p trnm-node --bin trnm-chain-cli
APP_BIN="$PWD/target/debug/trnm-cometbft-app"
CLI_BIN="$PWD/target/debug/trnm-chain-cli"

mkdir -p "$ROOT"
key_json="$($CLI_BIN keygen --output "$ROOT/operator.key")"
public_key="$(printf '%s' "$key_json" | jq -r .public_key_hex)"
for index in 0 1 2 3; do
  home="$ROOT/node$index"
  "$COMETBFT_BIN" init --home "$home" >/dev/null
  sed -i 's/^allow_duplicate_ip = false$/allow_duplicate_ip = true/' "$home/config/config.toml"
  jq -n \
    --arg public_key "$public_key" \
    --arg state_path "$home/app-state.json" \
    '{
      schema:"trnm_cometbft_app_config_v1",
      chain_id:"trnm-comet-four",
      authorized_signers:[{
        signer_id:"did:operator:1",
        signer_role:"operator",
        public_key_hex:$public_key
      }],
      state_path:$state_path
    }' > "$home/app.json"
done

validators="$(for index in 0 1 2 3; do jq '.validators[0]' "$ROOT/node$index/config/genesis.json"; done | jq -s '.')"
jq --argjson validators "$validators" \
  '.chain_id="trnm-comet-four" | .validators=$validators' \
  "$ROOT/node0/config/genesis.json" > "$ROOT/genesis.json"
for index in 0 1 2 3; do
  cp "$ROOT/genesis.json" "$ROOT/node$index/config/genesis.json"
done

node_ids=()
for index in 0 1 2 3; do
  node_ids+=("$($COMETBFT_BIN show-node-id --home "$ROOT/node$index")")
done

start_app() {
  local index="$1"
  local abci_port=$((BASE_ABCI + index * 10))
  "$APP_BIN" \
    --config "$ROOT/node$index/app.json" \
    --listen-addr "127.0.0.1:$abci_port" \
    >"$ROOT/node$index/app.log" 2>&1 &
  APP_PIDS[$index]=$!
}

start_comet() {
  local index="$1"
  local rpc_port=$((BASE_RPC + index * 10))
  local p2p_port=$((BASE_P2P + index * 10))
  local abci_port=$((BASE_ABCI + index * 10))
  local peers=()
  for peer in 0 1 2 3; do
    if [[ "$peer" != "$index" ]]; then
      peers+=("${node_ids[$peer]}@127.0.0.1:$((BASE_P2P + peer * 10))")
    fi
  done
  local peer_csv
  peer_csv="$(IFS=,; echo "${peers[*]}")"
  "$COMETBFT_BIN" start \
    --home "$ROOT/node$index" \
    --proxy_app "tcp://127.0.0.1:$abci_port" \
    --rpc.laddr "tcp://127.0.0.1:$rpc_port" \
    --p2p.laddr "tcp://127.0.0.1:$p2p_port" \
    --p2p.persistent_peers "$peer_csv" \
    --p2p.pex=false \
    --consensus.create_empty_blocks=false \
    >"$ROOT/node$index/comet.log" 2>&1 &
  COMET_PIDS[$index]=$!
}

wait_rpc() {
  local index="$1"
  local rpc_port=$((BASE_RPC + index * 10))
  for _ in $(seq 1 160); do
    if curl -fsS "http://127.0.0.1:$rpc_port/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_peers() {
  local index="$1"
  local expected="$2"
  local rpc_port=$((BASE_RPC + index * 10))
  local peer_count
  for _ in $(seq 1 200); do
    peer_count="$(curl -fsS "http://127.0.0.1:$rpc_port/net_info" 2>/dev/null | jq -r '.result.n_peers' || true)"
    if [[ "$peer_count" =~ ^[0-9]+$ ]] && (( peer_count >= expected )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_height() {
  local index="$1"
  local expected="$2"
  local rpc_port=$((BASE_RPC + index * 10))
  for _ in $(seq 1 200); do
    height="$(curl -fsS "http://127.0.0.1:$rpc_port/status" 2>/dev/null | jq -r '.result.sync_info.latest_block_height' || true)"
    if [[ "$height" =~ ^[0-9]+$ ]] && (( height >= expected )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

sign_tx() {
  local nonce="$1"
  printf 'four-validator-payload-%s' "$nonce" > "$ROOT/payload-$nonce.bin"
  "$CLI_BIN" sign \
    --private-key "$ROOT/operator.key" \
    --chain-id trnm-comet-four \
    --command-id "command-four-$nonce" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$nonce" \
    --payload-type opaque_fixture_v1 \
    --payload-file "$ROOT/payload-$nonce.bin" \
    --output "$ROOT/tx-$nonce.json" >/dev/null
}

broadcast_commit() {
  local tx_file="$1"
  local tx_b64
  tx_b64="$(base64 -w0 "$tx_file")"
  curl -fsS \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_commit\",\"params\":{\"tx\":\"$tx_b64\"}}" \
    "http://127.0.0.1:$BASE_RPC"
}

for index in 0 1 2 3; do start_app "$index"; done
for index in 0 1 2 3; do start_comet "$index"; done
for index in 0 1 2 3; do wait_rpc "$index"; done
for index in 0 1 2 3; do wait_peers "$index" 3; done

sign_tx 1
first="$(broadcast_commit "$ROOT/tx-1.json")"
test "$(printf '%s' "$first" | jq -r '.result.check_tx.code')" = "0"
test "$(printf '%s' "$first" | jq -r '.result.tx_result.code')" = "0"
first_height="$(printf '%s' "$first" | jq -r '.result.height | tonumber')"
for index in 0 1 2 3; do wait_height "$index" "$first_height"; done

app_hashes=()
for index in 0 1 2 3; do
  app_hashes+=("$(jq -r .app_hash_hex "$ROOT/node$index/app-state.json")")
done
test "$(printf '%s\n' "${app_hashes[@]}" | sort -u | wc -l)" = "1"

kill "${COMET_PIDS[3]}" "${APP_PIDS[3]}"
wait "${COMET_PIDS[3]}" 2>/dev/null || true
wait "${APP_PIDS[3]}" 2>/dev/null || true
COMET_PIDS[3]=""
APP_PIDS[3]=""

sign_tx 2
second="$(broadcast_commit "$ROOT/tx-2.json")"
test "$(printf '%s' "$second" | jq -r '.result.check_tx.code')" = "0"
test "$(printf '%s' "$second" | jq -r '.result.tx_result.code')" = "0"
second_height="$(printf '%s' "$second" | jq -r '.result.height | tonumber')"
rejoin_height=$((second_height + 1))
for index in 0 1 2; do wait_height "$index" "$rejoin_height"; done

start_app 3
start_comet 3
wait_rpc 3
wait_height 3 "$rejoin_height"
test "$(jq -r .height "$ROOT/node3/app-state.json")" = "$rejoin_height"

app_hashes=()
for index in 0 1 2 3; do
  app_hashes+=("$(jq -r .app_hash_hex "$ROOT/node$index/app-state.json")")
done
test "$(printf '%s\n' "${app_hashes[@]}" | sort -u | wc -l)" = "1"

printf 'TRNM_COMETBFT_FOUR_VALIDATOR_OK height=%s offline_tolerance=1 rejoin=verified app_hash=%s root=%s\n' \
  "$rejoin_height" "${app_hashes[0]}" "$ROOT"
