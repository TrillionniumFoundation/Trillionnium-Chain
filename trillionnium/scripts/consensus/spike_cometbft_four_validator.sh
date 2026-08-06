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
APP_CRASH_STAGES=("" "" "" "" "")
APP_CRASH_HEIGHTS=("" "" "" "" "")
APP_CRASH_MARKERS=("" "" "" "" "")
OPERATOR_ACCOUNT_NONCE=0
FIXTURE_COMMIT_RESPONSE=""
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
  cargo build -q -p trnm-consensus-app --bin trnm-cometbft-app --locked
  APP_BIN="$PWD/target/debug/trnm-cometbft-app"
fi
if [[ -z "$CLI_BIN" ]]; then
  cargo build -q -p trnm-node --features legacy-harness --bin trnm-chain-cli --locked
  CLI_BIN="$PWD/target/debug/trnm-chain-cli"
fi
test -x "$APP_BIN"
test -x "$CLI_BIN"

mkdir -p "$ROOT"
key_json="$($CLI_BIN keygen --output "$ROOT/operator.key")"
public_key="$(printf '%s' "$key_json" | jq -r .public_key_hex)"
client_public_key="$($CLI_BIN keygen --output "$ROOT/client.key" | jq -r .public_key_hex)"
worker_public_key="$($CLI_BIN keygen --output "$ROOT/worker.key" | jq -r .public_key_hex)"
consumer_public_key="$($CLI_BIN keygen --output "$ROOT/consumer.key" | jq -r .public_key_hex)"
challenger_public_key="$($CLI_BIN keygen --output "$ROOT/challenger.key" | jq -r .public_key_hex)"
authorized_signers="$(jq -n \
  --arg operator "$public_key" \
  --arg client "$client_public_key" \
  --arg worker "$worker_public_key" \
  --arg consumer "$consumer_public_key" \
  --arg challenger "$challenger_public_key" \
  '[
    {signer_id:"did:operator:1",signer_role:"operator",public_key_hex:$operator},
    {signer_id:"did:client:1",signer_role:"hepta",public_key_hex:$client},
    {signer_id:"did:worker:1",signer_role:"nakama",public_key_hex:$worker},
    {signer_id:"did:consumer:1",signer_role:"hepta",public_key_hex:$consumer},
    {signer_id:"did:challenger:1",signer_role:"hepta",public_key_hex:$challenger}
  ]')"
for index in 0 1 2 3 4; do
  home="$ROOT/node$index"
  "$COMETBFT_BIN" init --home "$home" >/dev/null
  sed -i 's/^allow_duplicate_ip = false$/allow_duplicate_ip = true/' "$home/config/config.toml"
  jq -n \
    --argjson authorized_signers "$authorized_signers" \
    --arg state_path "$home/app-state.json" \
    '{
      schema:"trnm_cometbft_app_config_v1",
      chain_id:"trnm-comet-four",
      authorized_signers:$authorized_signers,
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
jq --argjson validators "$validators" --argjson initial_validators "$initial_validators" --argjson authorized_signers "$authorized_signers" \
  '.chain_id="trnm-comet-four"
   | .validators=$validators
   | .consensus_params.version.app="5"
   | .app_state={
       schema:"trnm_cometbft_genesis_v3",
       chain_id:"trnm-comet-four",
       app_version:5,
       authorized_signers:$authorized_signers,
       research_authorities:{
         nakama_authorities:[],
         hepta_authorities:[]
       },
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
  local crash_args=()
  if [[ -n "${APP_CRASH_STAGES[index]}" ]]; then
    crash_args=(
      --unsafe-test-crash-stage "${APP_CRASH_STAGES[index]}"
      --unsafe-test-crash-height "${APP_CRASH_HEIGHTS[index]}"
      --unsafe-test-crash-marker "${APP_CRASH_MARKERS[index]}"
    )
  fi
  "$APP_BIN" \
    --config "$ROOT/node$index/app.json" \
    --listen-addr "127.0.0.1:$abci_port" \
    "${crash_args[@]}" \
    >"$ROOT/node$index/app.log" 2>&1 &
  APP_PIDS[index]=$!
}

configure_test_crash() {
  local index="$1"
  local stage="$2"
  local height="$3"
  APP_CRASH_STAGES[index]="$stage"
  APP_CRASH_HEIGHTS[index]="$height"
  APP_CRASH_MARKERS[index]="$ROOT/node$index/crash-$stage-$height.marker"
  test ! -e "${APP_CRASH_MARKERS[index]}"
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

wait_app_height() {
  local index="$1"
  local expected="$2"
  local status_path="$ROOT/node$index/app-state.json"
  local height
  for _ in $(seq 1 200); do
    height="$(jq -r '.height // empty' "$status_path" 2>/dev/null || true)"
    if [[ "$height" =~ ^[0-9]+$ ]] && (( height >= expected )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_test_crash() {
  local index="$1"
  local marker="${APP_CRASH_MARKERS[index]}"
  for _ in $(seq 1 200); do
    if [[ -s "$marker" ]] && ! kill -0 "${APP_PIDS[index]}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  printf 'test crash timed out: node=%s stage=%s height=%s marker=%s\n' \
    "$index" "${APP_CRASH_STAGES[index]}" "${APP_CRASH_HEIGHTS[index]}" "$marker" >&2
  return 1
}

crash_marker_appeared() {
  local index="$1"
  local marker="${APP_CRASH_MARKERS[index]}"
  for _ in $(seq 1 20); do
    [[ -s "$marker" ]] && return 0
    sleep 0.1
  done
  return 1
}

restart_node_after_test_crash() {
  local index="$1"
  local expected_height="$2"
  terminate_pids "${COMET_PIDS[index]}" "${APP_PIDS[index]}"
  COMET_PIDS[index]=""
  APP_PIDS[index]=""
  start_app "$index"
  start_comet "$index"
  wait_rpc "$index"
  wait_peers "$index" 2
  wait_height "$index" "$expected_height"
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
  local label="$1"
  local account_nonce=$((OPERATOR_ACCOUNT_NONCE + 1))
  jq -n \
    --arg sender did:operator:1 \
    --arg account "fixture:four:$label" \
    --argjson nonce "$account_nonce" \
    '{schema:"trnm_canonical_tx_v1",sender:$sender,nonce:$nonce,max_gas:100000,fee_limit:"100000",command:{type:"credit_account",account:$account,amount:"1"}}' \
    >"$ROOT/payload-$label.bin"
  "$CLI_BIN" sign \
    --private-key "$ROOT/operator.key" \
    --chain-id trnm-comet-four \
    --command-id "command-four-$label" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$account_nonce" \
    --payload-type trnm.canonical.tx.v1 \
    --payload-file "$ROOT/payload-$label.bin" \
    --output "$ROOT/tx-$label.json" >/dev/null
}

commit_fixture_tx() {
  local label="$1"
  sign_tx "$label"
  FIXTURE_COMMIT_RESPONSE="$(broadcast_commit "$ROOT/tx-$label.json")"
  test "$(printf '%s' "$FIXTURE_COMMIT_RESPONSE" | jq -r '.result.check_tx.code')" = "0"
  test "$(printf '%s' "$FIXTURE_COMMIT_RESPONSE" | jq -r '.result.tx_result.code')" = "0"
  OPERATOR_ACCOUNT_NONCE=$((OPERATOR_ACCOUNT_NONCE + 1))
}

sign_canonical_tx() {
  local label="$1"
  local signer_id="$2"
  local signer_role="$3"
  local private_key="$4"
  local envelope_nonce="$5"
  local payload="$6"
  local payload_file="$ROOT/vertical-$label.payload.json"
  local tx_file="$ROOT/vertical-$label.tx.json"
  printf '%s\n' "$payload" >"$payload_file"
  "$CLI_BIN" sign \
    --private-key "$private_key" \
    --chain-id trnm-comet-four \
    --command-id "vertical-$label" \
    --signer-id "$signer_id" \
    --signer-role "$signer_role" \
    --nonce "$envelope_nonce" \
    --payload-type trnm.canonical.tx.v1 \
    --payload-file "$payload_file" \
    --output "$tx_file" >/dev/null
  printf '%s\n' "$tx_file"
}

submit_canonical_tx() {
  local tx_file="$1"
  local expected_event="$2"
  local response
  response="$(broadcast_commit "$tx_file")"
  test "$(printf '%s' "$response" | jq -r '.result.check_tx.code')" = "0"
  test "$(printf '%s' "$response" | jq -r '.result.tx_result.code')" = "0"
  test "$(printf '%s' "$response" | jq -r '.result.tx_result.gas_used | tonumber')" -gt 0
  test "$(printf '%s' "$response" | jq -r --arg event "$expected_event" '.result.tx_result.events | any(.type == $event)')" = "true"
  printf '%s\n' "$response"
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

drive_until_test_crash() {
  local index="$1"
  shift
  local nonce
  for nonce in "$@"; do
    commit_fixture_tx "$nonce"
    if crash_marker_appeared "$index"; then
      break
    fi
  done
  wait_test_crash "$index"
}

for index in 0 1 2 3; do start_app "$index"; done
for index in 0 1 2 3; do start_comet "$index"; done
for index in 0 1 2 3; do wait_rpc "$index"; done
for index in 0 1 2 3; do wait_peers "$index" 2; done

commit_fixture_tx 1
first="$FIXTURE_COMMIT_RESPONSE"
first_height="$(printf '%s' "$first" | jq -r '.result.height | tonumber')"
for index in 0 1 2 3; do wait_height "$index" "$first_height"; done

wait_app_hash_convergence 0 1 2 3

# Crash while one validator is processing the next proposal. The other three
# validators must still finalize it, then the crashed validator must replay it.
current_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
proposal_height=$((current_height + 4))
terminate_pids "${COMET_PIDS[3]}" "${APP_PIDS[3]}"
configure_test_crash 3 process-proposal "$proposal_height"
start_app 3
start_comet 3
wait_rpc 3
wait_peers 3 2
drive_until_test_crash 3 proposal-a proposal-b proposal-c proposal-d proposal-e
wait_height 0 "$proposal_height"
second_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
test "$second_height" -ge "$proposal_height"
for index in 0 1 2; do wait_height "$index" "$second_height"; done
restart_node_after_test_crash 3 "$second_height"
wait_app_hash_convergence 0 1 2 3

# Crash after the consensus vote has selected a block but before the local
# application can finalize it. Replay must recover from the previous tip.
current_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
vote_height=$((current_height + 3))
terminate_pids "${COMET_PIDS[2]}" "${APP_PIDS[2]}"
configure_test_crash 2 finalize-block "$vote_height"
start_app 2
start_comet 2
wait_rpc 2
wait_peers 2 2
drive_until_test_crash 2 finalize-a finalize-b finalize-c finalize-d
wait_height 0 "$vote_height"
third_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
test "$third_height" -ge "$vote_height"
for index in 0 1 3; do wait_height "$index" "$third_height"; done
restart_node_after_test_crash 2 "$third_height"
wait_app_hash_convergence 0 1 2 3

# Crash after SQLite has durably committed but before ABCI Commit returns. The
# database tip must win over the stale JSON mirror during the handshake.
current_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
commit_height=$((current_height + 2))
terminate_pids "${COMET_PIDS[1]}" "${APP_PIDS[1]}"
configure_test_crash 1 commit-after-persist "$commit_height"
start_app 1
start_comet 1
wait_rpc 1
wait_peers 1 2
drive_until_test_crash 1 commit-a commit-b commit-c
wait_height 0 "$commit_height"
fourth_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
test "$fourth_height" -ge "$commit_height"
commit_persisted_height="$(python3 -c '
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    row = connection.execute(
        "SELECT value FROM metadata WHERE key = ?", ("height",)
    ).fetchone()
if row is None:
    raise SystemExit("missing persisted height")
print(row[0])
' "$ROOT/node1/app-state.json.sqlite3")"
test "$commit_persisted_height" = "$commit_height"
for index in 0 2 3; do wait_height "$index" "$fourth_height"; done
restart_node_after_test_crash 1 "$fourth_height"
test "$(jq -r .height "$ROOT/node1/app-state.json")" = "$fourth_height"
wait_app_hash_convergence 0 1 2 3

vertical_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
deadline_height=$((vertical_height + 40))
for credit in \
  'operator did:operator:1 100000' \
  'client did:client:1 200000' \
  'worker did:worker:1 100000' \
  'consumer did:consumer:1 100000' \
  'challenger did:challenger:1 100000'; do
  read -r label account amount <<<"$credit"
  operator_nonce=$((OPERATOR_ACCOUNT_NONCE + 1))
  payload="$(jq -nc \
    --arg sender did:operator:1 \
    --arg account "$account" \
    --arg amount "$amount" \
    --argjson nonce "$operator_nonce" \
    '{schema:"trnm_canonical_tx_v1",sender:$sender,nonce:$nonce,max_gas:100000,fee_limit:"100000",command:{type:"credit_account",account:$account,amount:$amount}}')"
  tx_file="$(sign_canonical_tx "credit-$label" did:operator:1 operator "$ROOT/operator.key" "$operator_nonce" "$payload")"
  submit_canonical_tx "$tx_file" account_credited >/dev/null
  OPERATOR_ACCOUNT_NONCE=$operator_nonce
done

payload="$(jq -nc --argjson deadline "$deadline_height" '{schema:"trnm_canonical_tx_v1",sender:"did:client:1",nonce:1,max_gas:100000,fee_limit:"100000",command:{type:"create_task",task_id:"canonical-task-1",reward:"10000",worker_stake:"5000",result_deadline_height:$deadline,challenge_window_blocks:40}}')"
tx_file="$(sign_canonical_tx create did:client:1 hepta "$ROOT/client.key" 1 "$payload")"
submit_canonical_tx "$tx_file" task_created >/dev/null

payload='{"schema":"trnm_canonical_tx_v1","sender":"did:client:1","nonce":2,"max_gas":100000,"fee_limit":"100000","command":{"type":"assign_task","task_id":"canonical-task-1","worker":"did:worker:1"}}'
tx_file="$(sign_canonical_tx forced-assign did:client:1 hepta "$ROOT/client.key" 2 "$payload")"
forced_assign_response="$(broadcast_commit "$tx_file")"
test "$(printf '%s' "$forced_assign_response" | jq -r '.result.check_tx.code')" != "0"

payload='{"schema":"trnm_canonical_tx_v1","sender":"did:worker:1","nonce":1,"max_gas":100000,"fee_limit":"100000","command":{"type":"assign_task","task_id":"canonical-task-1","worker":"did:worker:1"}}'
tx_file="$(sign_canonical_tx assign did:worker:1 nakama "$ROOT/worker.key" 1 "$payload")"
submit_canonical_tx "$tx_file" task_assigned >/dev/null

result_hash="$(printf canonical-result | sha256sum | cut -d' ' -f1)"
reveal_salt="$(printf canonical-reveal-salt | sha256sum | cut -d' ' -f1)"
commitment="$(python3 - "$result_hash" "$reveal_salt" <<'PY'
import hashlib
import sys

result_hash, reveal_salt = sys.argv[1:]
fields = [
    b"trnm.result-commitment.v1",
    b"canonical-task-1",
    b"did:worker:1",
    bytes.fromhex(result_hash),
    bytes.fromhex(reveal_salt),
]
digest = hashlib.sha256()
for field in fields:
    digest.update(len(field).to_bytes(8, "big"))
    digest.update(field)
print(digest.hexdigest())
PY
)"
payload="$(jq -nc --arg hash "$commitment" '{schema:"trnm_canonical_tx_v1",sender:"did:worker:1",nonce:2,max_gas:100000,fee_limit:"100000",command:{type:"commit_result",task_id:"canonical-task-1",commitment_hex:$hash}}')"
tx_file="$(sign_canonical_tx commit did:worker:1 nakama "$ROOT/worker.key" 2 "$payload")"
submit_canonical_tx "$tx_file" result_committed >/dev/null

replay_response="$(broadcast_commit "$tx_file")"
test "$(printf '%s' "$replay_response" | jq -r '.result.check_tx.code')" != "0"

payload="$(jq -nc --arg hash "$result_hash" --arg salt "$reveal_salt" '{schema:"trnm_canonical_tx_v1",sender:"did:worker:1",nonce:3,max_gas:100000,fee_limit:"100000",command:{type:"reveal_result",task_id:"canonical-task-1",result_hash_hex:$hash,reveal_salt_hex:$salt}}')"
tx_file="$(sign_canonical_tx reveal did:worker:1 nakama "$ROOT/worker.key" 3 "$payload")"
submit_canonical_tx "$tx_file" result_revealed >/dev/null

receipt_hash="$(printf canonical-consumption | sha256sum | cut -d' ' -f1)"
payload="$(jq -nc --arg hash "$receipt_hash" '{schema:"trnm_canonical_tx_v1",sender:"did:consumer:1",nonce:1,max_gas:100000,fee_limit:"100000",command:{type:"record_consumption",task_id:"canonical-task-1",units:100,payment:"2000",receipt_hash_hex:$hash}}')"
tx_file="$(sign_canonical_tx consume did:consumer:1 hepta "$ROOT/consumer.key" 1 "$payload")"
submit_canonical_tx "$tx_file" consumption_recorded >/dev/null

payload='{"schema":"trnm_canonical_tx_v1","sender":"did:client:1","nonce":2,"max_gas":1,"fee_limit":"100000","command":{"type":"transfer","to":"did:consumer:1","amount":"1"}}'
tx_file="$(sign_canonical_tx over-gas did:client:1 hepta "$ROOT/client.key" 3 "$payload")"
over_gas_response="$(broadcast_commit "$tx_file")"
test "$(printf '%s' "$over_gas_response" | jq -r '.result.check_tx.code')" != "0"

printf '{"unsupported":true}\n' >"$ROOT/vertical-unknown.payload.json"
"$CLI_BIN" sign \
  --private-key "$ROOT/client.key" \
  --chain-id trnm-comet-four \
  --command-id vertical-unknown \
  --signer-id did:client:1 \
  --signer-role hepta \
  --nonce 4 \
  --payload-type trnm.unknown.v1 \
  --payload-file "$ROOT/vertical-unknown.payload.json" \
  --output "$ROOT/vertical-unknown.tx.json" >/dev/null
unknown_response="$(broadcast_commit "$ROOT/vertical-unknown.tx.json")"
test "$(printf '%s' "$unknown_response" | jq -r '.result.check_tx.code')" != "0"

evidence_hash="$(printf canonical-evidence | sha256sum | cut -d' ' -f1)"
payload="$(jq -nc --arg hash "$evidence_hash" '{schema:"trnm_canonical_tx_v1",sender:"did:challenger:1",nonce:1,max_gas:100000,fee_limit:"100000",command:{type:"open_challenge",task_id:"canonical-task-1",bond:"1000",evidence_hash_hex:$hash}}')"
tx_file="$(sign_canonical_tx challenge did:challenger:1 hepta "$ROOT/challenger.key" 1 "$payload")"
submit_canonical_tx "$tx_file" challenge_opened >/dev/null

operator_nonce=$((OPERATOR_ACCOUNT_NONCE + 1))
payload="$(jq -nc --argjson nonce "$operator_nonce" '{schema:"trnm_canonical_tx_v1",sender:"did:operator:1",nonce:$nonce,max_gas:100000,fee_limit:"100000",command:{type:"resolve_challenge",task_id:"canonical-task-1",accept_challenge:false}}')"
tx_file="$(sign_canonical_tx resolve did:operator:1 operator "$ROOT/operator.key" "$operator_nonce" "$payload")"
submit_canonical_tx "$tx_file" challenge_resolved >/dev/null
OPERATOR_ACCOUNT_NONCE=$operator_nonce

operator_nonce=$((OPERATOR_ACCOUNT_NONCE + 1))
payload="$(jq -nc --argjson nonce "$operator_nonce" '{schema:"trnm_canonical_tx_v1",sender:"did:operator:1",nonce:$nonce,max_gas:100000,fee_limit:"0",command:{type:"set_fee_policy",gas_price:"1",base_gas:1000,byte_gas:2}}')"
tx_file="$(sign_canonical_tx fee-policy did:operator:1 operator "$ROOT/operator.key" "$operator_nonce" "$payload")"
submit_canonical_tx "$tx_file" fee_policy_updated >/dev/null
OPERATOR_ACCOUNT_NONCE=$operator_nonce

operator_nonce=$((OPERATOR_ACCOUNT_NONCE + 1))
payload="$(jq -nc --argjson nonce "$operator_nonce" '{schema:"trnm_canonical_tx_v1",sender:"did:operator:1",nonce:$nonce,max_gas:100000,fee_limit:"0",command:{type:"distribute_fees",to:"did:treasury:1",amount:"1"}}')"
tx_file="$(sign_canonical_tx distribute-fees did:operator:1 operator "$ROOT/operator.key" "$operator_nonce" "$payload")"
submit_canonical_tx "$tx_file" fees_distributed >/dev/null
OPERATOR_ACCOUNT_NONCE=$operator_nonce

expiry_base_height="$(curl -fsS "http://127.0.0.1:$BASE_RPC/status" | jq -r '.result.sync_info.latest_block_height | tonumber')"
expiry_deadline=$((expiry_base_height + 2))
payload="$(jq -nc --argjson deadline "$expiry_deadline" '{schema:"trnm_canonical_tx_v1",sender:"did:client:1",nonce:2,max_gas:100000,fee_limit:"100000",command:{type:"create_task",task_id:"canonical-expiry-1",reward:"1000",worker_stake:"500",result_deadline_height:$deadline,challenge_window_blocks:10}}')"
tx_file="$(sign_canonical_tx expiry-create did:client:1 hepta "$ROOT/client.key" 2 "$payload")"
submit_canonical_tx "$tx_file" task_created >/dev/null

payload='{"schema":"trnm_canonical_tx_v1","sender":"did:client:1","nonce":3,"max_gas":100000,"fee_limit":"100000","command":{"type":"expire_task","task_id":"canonical-expiry-1"}}'
tx_file="$(sign_canonical_tx expiry-finalize did:client:1 hepta "$ROOT/client.key" 3 "$payload")"
expiry_response="$(submit_canonical_tx "$tx_file" task_expired)"
vertical_final_height="$(printf '%s' "$expiry_response" | jq -r '.result.height | tonumber')"
test "$vertical_final_height" -ge "$expiry_deadline"
for index in 0 1 2 3; do wait_height "$index" "$vertical_final_height"; done
wait_app_hash_convergence 0 1 2 3

task_query="$(curl -fsS -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"abci_query","params":{"path":"/task/canonical-task-1","data":"","height":"0","prove":false}}' \
  "http://127.0.0.1:$BASE_RPC")"
test "$(printf '%s' "$task_query" | jq -r '.result.response.code')" = "0"
test "$(printf '%s' "$task_query" | jq -r '.result.response.log')" = "trnm.poco.task.v1"
queried_task_status="$(printf '%s' "$task_query" | jq -r '.result.response.value' | base64 -d | jq -r .status)"
test "$queried_task_status" = "resolved_for_worker"
expiry_query="$(curl -fsS -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"abci_query","params":{"path":"/task/canonical-expiry-1","data":"","height":"0","prove":false}}' \
  "http://127.0.0.1:$BASE_RPC")"
test "$(printf '%s' "$expiry_query" | jq -r '.result.response.code')" = "0"
test "$(printf '%s' "$expiry_query" | jq -r '.result.response.value' | base64 -d | jq -r .status)" = "expired"
proof_query="$(curl -fsS -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"abci_query","params":{"path":"/task/canonical-task-1","data":"","height":"0","prove":true}}' \
  "http://127.0.0.1:$BASE_RPC")"
test "$(printf '%s' "$proof_query" | jq -r '.result.response.code')" = "0"
test "$(printf '%s' "$proof_query" | jq -r '.result.response.log')" = "trnm.poco.task.v1"
test "$(
  printf '%s' "$proof_query" |
    jq -r '(.result.response.proofOps.ops // .result.response.proof_ops.ops // []) | length'
)" = "1"
test "$(
  printf '%s' "$proof_query" |
    jq -r '(.result.response.proofOps.ops // .result.response.proof_ops.ops)[0].type'
)" = "ics23:jmt:v1"
test -n "$(
  printf '%s' "$proof_query" |
    jq -r '(.result.response.proofOps.ops // .result.response.proof_ops.ops)[0].key'
)"
test -n "$(
  printf '%s' "$proof_query" |
    jq -r '(.result.response.proofOps.ops // .result.response.proof_ops.ops)[0].data'
)"

for nonce in 14 15 16 17; do
  commit_fixture_tx "$nonce"
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
wait_app_height 4 "$latest_height"

wait_app_hash_convergence 0 1 2 3 4
final_height="$(jq -r .height "$ROOT/node4/app-state.json")"
app_hash="$(jq -r .app_hash_hex "$ROOT/node4/app-state.json")"
state_sync_line="$(
  grep -E 'Snapshot restored.*height=[0-9]+.*format=4' "$ROOT/node4/comet.log" |
    tail -n 1
)"
test -n "$state_sync_line"
state_sync_height="$(
  printf '%s\n' "$state_sync_line" |
    sed -n 's/.*height=\([0-9][0-9]*\).*format=4.*/\1/p'
)"
test "$state_sync_height" -gt 0
test "$state_sync_height" -le "$latest_height"
state_sync_app_hash="$(
  grep -E "Verified ABCI app.*height=$state_sync_height.*appHash=[0-9A-F]+" \
    "$ROOT/node4/comet.log" |
    tail -n 1 |
    sed -n 's/.*appHash=\([0-9A-F][0-9A-F]*\).*/\1/p'
)"
test "${#state_sync_app_hash}" -eq 64

evidence_dir="$ROOT/evidence"
mkdir -p -- "$evidence_dir"
jq -n \
  --argjson snapshot_height "$state_sync_height" \
  --arg snapshot_app_hash "$state_sync_app_hash" \
  --argjson final_height "$final_height" \
  '{
    schema:"trnm_cometbft_state_sync_evidence_v1",
    node:"node4",
    snapshot_format:4,
    snapshot_height:$snapshot_height,
    snapshot_app_hash:$snapshot_app_hash,
    light_client_and_abci_app:"verified",
    recovery:"restored_and_caught_up",
    final_height:$final_height
  }' >"$evidence_dir/state-sync-evidence.json"
jq -n \
  --argjson proposal_target_height "$proposal_height" \
  --argjson proposal_observed_tip "$second_height" \
  --arg proposal_marker "$(cat "${APP_CRASH_MARKERS[3]}")" \
  --argjson vote_finalize_target_height "$vote_height" \
  --argjson vote_finalize_observed_tip "$third_height" \
  --arg vote_finalize_marker "$(cat "${APP_CRASH_MARKERS[2]}")" \
  --argjson commit_target_height "$commit_height" \
  --argjson commit_observed_tip "$fourth_height" \
  --argjson commit_persisted_height "$commit_persisted_height" \
  --arg commit_marker "$(cat "${APP_CRASH_MARKERS[1]}")" \
  '{
    schema:"trnm_cometbft_crash_boundary_evidence_v1",
    stages:[
      {
        stage:"process_proposal",
        node:"node3",
        target_height:$proposal_target_height,
        observed_tip:$proposal_observed_tip,
        marker:$proposal_marker,
        recovery:"replayed_and_converged"
      },
      {
        stage:"finalize_block",
        node:"node2",
        target_height:$vote_finalize_target_height,
        observed_tip:$vote_finalize_observed_tip,
        marker:$vote_finalize_marker,
        recovery:"replayed_and_converged"
      },
      {
        stage:"commit_after_persist",
        node:"node1",
        target_height:$commit_target_height,
        observed_tip:$commit_observed_tip,
        persisted_height:$commit_persisted_height,
        marker:$commit_marker,
        recovery:"sqlite_tip_won_and_converged"
      }
    ]
  }' >"$evidence_dir/crash-boundary-evidence.json"
python3 - \
  "$ROOT/node0/app-state.json.sqlite3" \
  "$ROOT/node1/app-state.json.sqlite3" \
  "$ROOT/node2/app-state.json.sqlite3" \
  "$ROOT/node3/app-state.json.sqlite3" \
  "$OPERATOR_ACCOUNT_NONCE" \
  "$evidence_dir/canonical-vertical-slice.json" <<'PY'
import hashlib
import json
import sqlite3
import sys

*database_args, expected_operator_nonce, output = sys.argv[1:]
databases = database_args
node_rows = []
for database in databases:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT object_key_hex, object_type, version, value_bytes FROM objects ORDER BY object_key_hex"
        ).fetchall()
    node_rows.append(rows)
assert all(rows == node_rows[0] for rows in node_rows[1:]), "canonical objects diverged across validators"

objects = [json.loads(value) for _, _, _, value in node_rows[0]]
task = next(item for item in objects if item.get("task_id") == "canonical-task-1")
expired_task = next(item for item in objects if item.get("task_id") == "canonical-expiry-1")
accounts = {item["account"]: item for item in objects if "account" in item}
monetary = next(item for item in objects if "total_issued" in item)
fee_policy = next(item for item in objects if "gas_price" in item and "base_gas" in item)
assert task["status"] == "resolved_for_worker"
assert expired_task["status"] == "expired"
assert accounts["did:operator:1"]["nonce"] == int(expected_operator_nonce)
assert accounts["did:client:1"]["nonce"] == 3
assert accounts["did:worker:1"]["nonce"] == 3
assert accounts["did:consumer:1"]["nonce"] == 1
assert accounts["did:challenger:1"]["nonce"] == 1
assert int(accounts["did:treasury:1"]["balance"]) == 1
assert int(accounts["did:worker:1"]["balance"]) > 100_000
assert int(accounts["trnm:fee:collector"]["balance"]) > 0
assert fee_policy == {"gas_price": "1", "base_gas": 1000, "byte_gas": 2}
assert sum(int(account["balance"]) for account in accounts.values()) == int(monetary["total_issued"])
state_digest = hashlib.sha256()
for key, object_type, version, value in node_rows[0]:
    for field in (key.encode(), object_type.encode(), str(version).encode(), bytes(value)):
        state_digest.update(len(field).to_bytes(8, "big"))
        state_digest.update(field)
with open(output, "w", encoding="utf-8") as handle:
    json.dump({
        "schema": "trnm_canonical_vertical_slice_evidence_v1",
        "task": task,
        "expired_task": expired_task,
        "accounts": accounts,
        "monetary_state": monetary,
        "fee_policy": fee_policy,
        "validator_count": len(databases),
        "canonical_state_digest": state_digest.hexdigest(),
        "rejections": {
            "forced_worker_assignment": "rejected",
            "replay": "rejected",
            "over_gas": "rejected",
            "unknown_payload": "rejected",
            "proof_before_apphash_v4": "rejected",
        },
    }, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
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

printf 'TRNM_COMETBFT_FOUR_VALIDATOR_OK height=%s canonical_vertical_slice=verified crash_proposal=verified crash_vote_finalize=verified crash_commit_after_persist=verified state_sync=verified safety_evidence=verified app_hash=%s root=%s\n' \
  "$final_height" "$app_hash" "$ROOT"
