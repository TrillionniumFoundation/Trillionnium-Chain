#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"
KEEP="${TRNM_COMETBFT_SPIKE_KEEP:-0}"
CLEAN_ON_SUCCESS="${TRNM_COMETBFT_SPIKE_CLEAN_ON_SUCCESS:-}"
BASE_RPC="${TRNM_COMETBFT_BASE_RPC_PORT:-28657}"
BASE_P2P="${TRNM_COMETBFT_BASE_P2P_PORT:-28656}"
BASE_ABCI="${TRNM_COMETBFT_BASE_ABCI_PORT:-28658}"
APP_PIDS=("" "" "" "" "")
COMET_PIDS=("" "" "" "" "")
ROOT_CREATED_BY_SCRIPT=0
ROOT_MARKER_NAME=".trnm-comet-four-root-v1"
ROOT_MARKER_VALUE="trnm-comet-four-root-v1"

if [[ -n "${TRNM_COMETBFT_SPIKE_ROOT:-}" ]]; then
  ROOT="$TRNM_COMETBFT_SPIKE_ROOT"
  if [[ ! -e "$ROOT" ]]; then
    mkdir -p -- "$ROOT"
    ROOT_CREATED_BY_SCRIPT=1
  elif [[ ! -d "$ROOT" ]]; then
    printf 'TRNM_COMETBFT_FOUR_VALIDATOR_FAILED reason=root_is_not_directory root=%s\n' \
      "$ROOT" >&2
    exit 2
  fi
  CLEAN_ON_SUCCESS="${CLEAN_ON_SUCCESS:-0}"
else
  ROOT="$(mktemp -d /tmp/trnm-comet-four.XXXXXX)"
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
  [[ "$base" == trnm-comet-four.* || "$base" == trnm-comet-four-* ]]
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
  terminate_pids "${COMET_PIDS[@]}" "${APP_PIDS[@]}"
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
trap 'printf "TRNM_COMETBFT_FOUR_VALIDATOR_FAILED line=%s root=%s\n" "$LINENO" "$ROOT" >&2' ERR

command -v "$COMETBFT_BIN" >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
command -v base64 >/dev/null
command -v python3 >/dev/null

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

mkdir -p "$ROOT"
key_json="$($CLI_BIN keygen --output "$ROOT/operator.key")"
public_key="$(printf '%s' "$key_json" | jq -r .public_key_hex)"
for index in 0 1 2 3 4; do
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
initial_validators="$(printf '%s' "$validators" | python3 -c '
import base64
import json
import sys

validators = json.load(sys.stdin)
result = [
    {
        "public_key_hex": base64.b64decode(validator["pub_key"]["value"]).hex(),
        "voting_power": int(validator["power"]),
    }
    for validator in validators
]
result.sort(key=lambda validator: validator["public_key_hex"])
print(json.dumps(result, separators=(",", ":")))
')"
jq --argjson validators "$validators" --argjson initial_validators "$initial_validators" --arg public_key "$public_key" \
  '.chain_id="trnm-comet-four"
   | .validators=$validators
   | .consensus_params.version.app="3"
   | .app_state={
       schema:"trnm_cometbft_genesis_v2",
       chain_id:"trnm-comet-four",
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
         unsafe_allow_single_validator_genesis:false
       },
       initial_validators:$initial_validators
     }' \
  "$ROOT/node0/config/genesis.json" > "$ROOT/genesis.json"
for index in 0 1 2 3 4; do
  cp "$ROOT/genesis.json" "$ROOT/node$index/config/genesis.json"
done

node_ids=()
for index in 0 1 2 3 4; do
  node_ids+=("$($COMETBFT_BIN show-node-id --home "$ROOT/node$index")")
done

start_app() {
  local index="$1"
  local abci_port=$((BASE_ABCI + index * 10))
  "$APP_BIN" \
    --config "$ROOT/node$index/app.json" \
    --listen-addr "127.0.0.1:$abci_port" \
    >"$ROOT/node$index/app.log" 2>&1 &
  APP_PIDS[index]=$!
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
  COMET_PIDS[index]=$!
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

wait_app_hash_convergence() {
  local indexes=("$@")
  local hashes=()
  local index
  for _ in $(seq 1 200); do
    hashes=()
    for index in "${indexes[@]}"; do
      if [[ ! -f "$ROOT/node$index/app-state.json" ]]; then
        hashes+=("missing-$index")
      else
        hashes+=("$(jq -r '.height | tostring' "$ROOT/node$index/app-state.json"):$(jq -r .app_hash_hex "$ROOT/node$index/app-state.json")")
      fi
    done
    if [[ "$(printf '%s\n' "${hashes[@]}" | sort -u | wc -l)" = "1" ]]; then
      return 0
    fi
    sleep 0.25
  done
  printf 'app state convergence timed out: %s\n' "${hashes[*]}" >&2
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
for index in 0 1 2 3; do wait_peers "$index" 2; done

sign_tx 1
first="$(broadcast_commit "$ROOT/tx-1.json")"
test "$(printf '%s' "$first" | jq -r '.result.check_tx.code')" = "0"
test "$(printf '%s' "$first" | jq -r '.result.tx_result.code')" = "0"
first_height="$(printf '%s' "$first" | jq -r '.result.height | tonumber')"
for index in 0 1 2 3; do wait_height "$index" "$first_height"; done

wait_app_hash_convergence 0 1 2 3

terminate_pids "${COMET_PIDS[3]}" "${APP_PIDS[3]}"
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

wait_app_hash_convergence 0 1 2 3

for nonce in 3 4 5 6; do
  sign_tx "$nonce"
  committed="$(broadcast_commit "$ROOT/tx-$nonce.json")"
  test "$(printf '%s' "$committed" | jq -r '.result.check_tx.code')" = "0"
  test "$(printf '%s' "$committed" | jq -r '.result.tx_result.code')" = "0"
done
latest_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
for index in 0 1 2 3; do wait_height "$index" "$latest_height"; done
trust_height=$((latest_height - 2))
test "$trust_height" -gt 0
trust_hash="$(curl -fsS "http://127.0.0.1:$BASE_RPC/block?height=$trust_height" | jq -r '.result.block_id.hash')"
test -n "$trust_hash"

python3 - "$ROOT/node4/config/config.toml" \
  "http://127.0.0.1:$BASE_RPC,http://127.0.0.1:$((BASE_RPC + 10))" \
  "$trust_height" "$trust_hash" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
rpc_servers = sys.argv[2]
trust_height = sys.argv[3]
trust_hash = sys.argv[4]
text = path.read_text()
start = text.index("[statesync]")
end = text.index("\n[", start + 1)
section = text[start:end]
section = section.replace("enable = false", "enable = true", 1)
section = section.replace('rpc_servers = ""', f'rpc_servers = "{rpc_servers}"', 1)
section = section.replace("trust_height = 0", f"trust_height = {trust_height}", 1)
section = section.replace('trust_hash = ""', f'trust_hash = "{trust_hash}"', 1)
section = section.replace('discovery_time = "15s"', 'discovery_time = "6s"', 1)
path.write_text(text[:start] + section + text[end:])
PY

test ! -e "$ROOT/node4/app-state.json"
start_app 4
start_comet 4
wait_rpc 4
wait_peers 4 2
wait_height 4 "$latest_height"
test "$(jq -r .height "$ROOT/node4/app-state.json")" -ge "$latest_height"

wait_app_hash_convergence 0 1 2 3 4
final_height="$(jq -r .height "$ROOT/node4/app-state.json")"
app_hash="$(jq -r .app_hash_hex "$ROOT/node4/app-state.json")"

evidence_dir="$ROOT/evidence"
mkdir -p -- "$evidence_dir"
python3 "$SCRIPT_DIR/assert_cometbft_safety.py" \
  --expected-chain-id trnm-comet-four \
  --json-out "$evidence_dir/safety-evidence.json" \
  --tsv-out "$evidence_dir/safety-evidence.tsv" \
  --history-node node0 \
  --history-node node1 \
  --history-node node2 \
  --history-node node3 \
  --node node0 "http://127.0.0.1:$BASE_RPC" "$ROOT/node0/app-state.json" \
  --node node1 "http://127.0.0.1:$((BASE_RPC + 10))" "$ROOT/node1/app-state.json" \
  --node node2 "http://127.0.0.1:$((BASE_RPC + 20))" "$ROOT/node2/app-state.json" \
  --node node3 "http://127.0.0.1:$((BASE_RPC + 30))" "$ROOT/node3/app-state.json" \
  --node node4 "http://127.0.0.1:$((BASE_RPC + 40))" "$ROOT/node4/app-state.json"
test "$(jq -r .common_tip_height "$evidence_dir/safety-evidence.json")" = "$final_height"

printf 'TRNM_COMETBFT_FOUR_VALIDATOR_OK height=%s offline_tolerance=1 rejoin=verified state_sync=verified safety_evidence=verified app_hash=%s root=%s\n' \
  "$final_height" "$app_hash" "$ROOT"
