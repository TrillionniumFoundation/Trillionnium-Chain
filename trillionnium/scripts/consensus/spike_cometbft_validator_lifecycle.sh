#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

CHAIN_ID="${TRNM_COMETBFT_LIFECYCLE_CHAIN_ID:-trnm-comet-lifecycle}"
COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"
EXPECTED_COMETBFT_VERSION="${TRNM_COMETBFT_EXPECTED_VERSION:-0.38.17}"
BASE_RPC="${TRNM_COMETBFT_LIFECYCLE_BASE_RPC_PORT:-${TRNM_COMETBFT_BASE_RPC_PORT:-29657}}"
BASE_P2P="${TRNM_COMETBFT_LIFECYCLE_BASE_P2P_PORT:-${TRNM_COMETBFT_BASE_P2P_PORT:-29656}}"
BASE_ABCI="${TRNM_COMETBFT_LIFECYCLE_BASE_ABCI_PORT:-${TRNM_COMETBFT_BASE_ABCI_PORT:-29658}}"
KEEP="${TRNM_COMETBFT_LIFECYCLE_KEEP:-${TRNM_COMETBFT_SPIKE_KEEP:-0}}"
CLEAN_ON_SUCCESS="${TRNM_COMETBFT_LIFECYCLE_CLEAN_ON_SUCCESS:-}"
APP_PIDS=("" "" "" "" "" "")
COMET_PIDS=("" "" "" "" "" "")
ROOT_CREATED_BY_SCRIPT=0
ROOT_MARKER_NAME=".trnm-comet-lifecycle-root-v1"
ROOT_MARKER_VALUE="trnm-comet-lifecycle-root-v1"
HELPER="$SCRIPT_DIR/validator_lifecycle_fixture.py"

if [[ -n "${TRNM_COMETBFT_LIFECYCLE_ROOT:-}" ]]; then
  ROOT="$TRNM_COMETBFT_LIFECYCLE_ROOT"
  if [[ ! -e "$ROOT" ]]; then
    mkdir -p -- "$ROOT"
    ROOT_CREATED_BY_SCRIPT=1
  elif [[ ! -d "$ROOT" ]]; then
    printf 'TRNM_COMETBFT_VALIDATOR_LIFECYCLE_FAILED reason=root_is_not_directory root=%s\n' \
      "$ROOT" >&2
    exit 2
  fi
  CLEAN_ON_SUCCESS="${CLEAN_ON_SUCCESS:-0}"
else
  ROOT="$(mktemp -d /tmp/trnm-comet-lifecycle.XXXXXX)"
  ROOT_CREATED_BY_SCRIPT=1
  CLEAN_ON_SUCCESS="${CLEAN_ON_SUCCESS:-1}"
fi
chmod 700 "$ROOT"
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
  [[ "$base" == trnm-comet-lifecycle.* || "$base" == trnm-comet-lifecycle-* ]]
}

cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${COMET_PIDS[@]}" "${APP_PIDS[@]}"; do
    test -z "$pid" || kill "$pid" 2>/dev/null || true
  done
  for pid in "${COMET_PIDS[@]}" "${APP_PIDS[@]}"; do
    test -z "$pid" || wait "$pid" 2>/dev/null || true
  done
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
trap 'printf "TRNM_COMETBFT_VALIDATOR_LIFECYCLE_FAILED line=%s root=%s\n" "$LINENO" "$ROOT" >&2' ERR

for value in "$BASE_RPC" "$BASE_P2P" "$BASE_ABCI"; do
  [[ "$value" =~ ^[0-9]+$ ]]
  (( value >= 1024 && value + 50 <= 65535 ))
done
[[ "$CHAIN_ID" =~ ^[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]$ ]]

command -v "$COMETBFT_BIN" >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
command -v base64 >/dev/null
command -v python3 >/dev/null
test -f "$HELPER"
test "$("$COMETBFT_BIN" version)" = "$EXPECTED_COMETBFT_VERSION"
python3 -c 'import cryptography' >/dev/null

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

mkdir -p -- "$ROOT/evidence/phases"
key_json="$("$CLI_BIN" keygen --output "$ROOT/operator.key")"
operator_public_key="$(printf '%s' "$key_json" | jq -er .public_key_hex)"

for index in 0 1 2 3 4 5; do
  home="$ROOT/node$index"
  "$COMETBFT_BIN" init --home "$home" >/dev/null
  sed -i 's/^allow_duplicate_ip = false$/allow_duplicate_ip = true/' "$home/config/config.toml"
  sed -i 's/^create_empty_blocks = true$/create_empty_blocks = false/' "$home/config/config.toml"
  test "$(sed -n 's/^create_empty_blocks = //p' "$home/config/config.toml")" = "false"
  jq -n \
    --arg chain_id "$CHAIN_ID" \
    --arg public_key "$operator_public_key" \
    --arg state_path "$home/app-state.json" \
    '{
      schema:"trnm_cometbft_app_config_v1",
      chain_id:$chain_id,
      authorized_signers:[{
        signer_id:"did:operator:1",
        signer_role:"operator",
        public_key_hex:$public_key
      }],
      state_path:$state_path
    }' >"$home/app.json"
done

python3 "$HELPER" validator-set --power 10 \
  --key "$ROOT/node0/config/priv_validator_key.json" \
  --key "$ROOT/node1/config/priv_validator_key.json" \
  --key "$ROOT/node2/config/priv_validator_key.json" \
  --key "$ROOT/node3/config/priv_validator_key.json" \
  --output "$ROOT/validator-set-initial-4.json"
python3 "$HELPER" validator-set --power 10 \
  --key "$ROOT/node0/config/priv_validator_key.json" \
  --key "$ROOT/node1/config/priv_validator_key.json" \
  --key "$ROOT/node2/config/priv_validator_key.json" \
  --key "$ROOT/node3/config/priv_validator_key.json" \
  --key "$ROOT/node4/config/priv_validator_key.json" \
  --output "$ROOT/validator-set-added-5.json"
python3 "$HELPER" validator-set --power 10 \
  --key "$ROOT/node1/config/priv_validator_key.json" \
  --key "$ROOT/node2/config/priv_validator_key.json" \
  --key "$ROOT/node3/config/priv_validator_key.json" \
  --key "$ROOT/node4/config/priv_validator_key.json" \
  --output "$ROOT/validator-set-removed-4.json"
python3 "$HELPER" validator-set --power 10 \
  --key "$ROOT/node2/config/priv_validator_key.json" \
  --key "$ROOT/node3/config/priv_validator_key.json" \
  --key "$ROOT/node4/config/priv_validator_key.json" \
  --key "$ROOT/node5/config/priv_validator_key.json" \
  --output "$ROOT/validator-set-rotated-4.json"

genesis_validators="$(
  for index in 0 1 2 3; do
    jq '.validators[0]' "$ROOT/node$index/config/genesis.json"
  done | jq -s '.'
)"
initial_validators="$(cat "$ROOT/validator-set-initial-4.json")"
jq \
  --arg chain_id "$CHAIN_ID" \
  --arg public_key "$operator_public_key" \
  --argjson validators "$genesis_validators" \
  --argjson initial_validators "$initial_validators" \
  '.chain_id=$chain_id
   | .validators=$validators
   | .consensus_params.version.app="3"
   | .app_state={
       schema:"trnm_cometbft_genesis_v2",
       chain_id:$chain_id,
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
  "$ROOT/node0/config/genesis.json" >"$ROOT/genesis.json"
for index in 0 1 2 3 4 5; do
  cp "$ROOT/genesis.json" "$ROOT/node$index/config/genesis.json"
done

node_ids=()
for index in 0 1 2 3 4 5; do
  node_ids+=("$("$COMETBFT_BIN" show-node-id --home "$ROOT/node$index")")
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
  local peer
  for peer in 0 1 2 3 4 5; do
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
    --rpc.unsafe=true \
    --consensus.create_empty_blocks=false \
    >"$ROOT/node$index/comet.log" 2>&1 &
  COMET_PIDS[index]=$!
}

wait_rpc() {
  local index="$1"
  local rpc_port=$((BASE_RPC + index * 10))
  for _ in $(seq 1 200); do
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
  for _ in $(seq 1 240); do
    peer_count="$(
      curl -fsS "http://127.0.0.1:$rpc_port/net_info" 2>/dev/null |
        jq -r '.result.n_peers' || true
    )"
    if [[ "$peer_count" =~ ^[0-9]+$ ]] && (( peer_count >= expected )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

latest_height() {
  curl -fsS "http://127.0.0.1:$BASE_RPC/status" |
    jq -er '.result.sync_info.latest_block_height | tonumber'
}

wait_height() {
  local index="$1"
  local expected="$2"
  local rpc_port=$((BASE_RPC + index * 10))
  local height
  for _ in $(seq 1 240); do
    height="$(
      curl -fsS "http://127.0.0.1:$rpc_port/status" 2>/dev/null |
        jq -r '.result.sync_info.latest_block_height' || true
    )"
    if [[ "$height" =~ ^[0-9]+$ ]] && (( height >= expected )); then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_app_hash_convergence() {
  local expected_height="$1"
  local hashes=()
  local index
  local height
  local app_hash
  for _ in $(seq 1 240); do
    hashes=()
    for index in 0 1 2 3 4 5; do
      if [[ ! -f "$ROOT/node$index/app-state.json" ]]; then
        hashes+=("missing-$index")
        continue
      fi
      height="$(jq -r '.height // empty' "$ROOT/node$index/app-state.json")"
      app_hash="$(jq -r '.app_hash_hex // empty' "$ROOT/node$index/app-state.json")"
      hashes+=("$height:$app_hash")
    done
    if [[ "$(printf '%s\n' "${hashes[@]}" | sort -u | wc -l)" = "1" ]] &&
      [[ "${hashes[0]%%:*}" = "$expected_height" ]]; then
      return 0
    fi
    sleep 0.25
  done
  printf 'app state convergence timed out at height %s: %s\n' \
    "$expected_height" "${hashes[*]}" >&2
  return 1
}

wait_settled_height_at_or_after() {
  local minimum_height="$1"
  local previous=""
  local current
  local stable_samples=0
  local index
  local states
  for _ in $(seq 1 240); do
    current="$(latest_height)"
    if (( current < minimum_height )); then
      previous="$current"
      stable_samples=0
      sleep 0.25
      continue
    fi
    states="$({
      for index in 0 1 2 3 4 5; do
        jq -r '[.height, .app_hash_hex] | @tsv' "$ROOT/node$index/app-state.json" \
          2>/dev/null || printf 'missing-%s\n' "$index"
      done
    } | sort -u)"
    if [[ "$(printf '%s\n' "$states" | wc -l)" = "1" ]] &&
      [[ "${states%%$'\t'*}" = "$current" ]] &&
      [[ "$current" = "$previous" ]]; then
      stable_samples=$((stable_samples + 1))
      if (( stable_samples >= 12 )); then
        printf '%s\n' "$current"
        return 0
      fi
    else
      stable_samples=0
    fi
    previous="$current"
    sleep 0.25
  done
  printf 'validator lifecycle network did not settle at or after height %s\n' \
    "$minimum_height" >&2
  return 1
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

flush_mempools() {
  local index
  for index in 0 1 2 3 4 5; do
    curl -fsS \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"unsafe_flush_mempool","params":{}}' \
      "http://127.0.0.1:$((BASE_RPC + index * 10))" |
      jq -e '.result != null' >/dev/null
  done
}

assert_committed_response() {
  local response="$1"
  local expected_height="$2"
  if [[ "$(printf '%s' "$response" | jq -r '.error != null')" = "true" ]] ||
    [[ "$(printf '%s' "$response" | jq -r '.result.check_tx.code // -1')" != "0" ]] ||
    [[ "$(printf '%s' "$response" | jq -r '.result.tx_result.code // -1')" != "0" ]]; then
    printf 'validator lifecycle transaction rejected: %s\n' \
      "$(printf '%s' "$response" | jq -c '{error, check_tx:.result.check_tx, tx_result:.result.tx_result, height:.result.height}')" \
      >&2
    return 1
  fi
  test "$(printf '%s' "$response" | jq -er '.result.check_tx.code')" = "0"
  test "$(printf '%s' "$response" | jq -er '.result.tx_result.code')" = "0"
  test "$(printf '%s' "$response" | jq -er '.result.height | tonumber')" = "$expected_height"
}

SUBMITTED_HEIGHT=0
SUBMITTED_ACTIVATION=0
submit_transition() {
  local label="$1"
  local nonce="$2"
  local base_set="$3"
  local target_set="$4"
  shift 4
  local proof_args=()
  local proof
  for proof in "$@"; do
    proof_args+=(--proof-key "$proof")
  done
  local current
  current="$(latest_height)"
  local projected_height=$((current + 1))
  SUBMITTED_ACTIVATION=$((current + 4))
  local transition_id="validator-$label-$projected_height"
  local payload="$ROOT/$transition_id.json"
  local tx="$ROOT/$transition_id.tx.json"
  python3 "$HELPER" transition \
    --chain-id "$CHAIN_ID" \
    --transition-id "$transition_id" \
    --activation-height "$SUBMITTED_ACTIVATION" \
    --base-set "$base_set" \
    --target-set "$target_set" \
    "${proof_args[@]}" \
    --output "$payload"
  "$CLI_BIN" sign \
    --private-key "$ROOT/operator.key" \
    --chain-id "$CHAIN_ID" \
    --command-id "$transition_id" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$nonce" \
    --payload-type trnm_validator_set_transition_v1 \
    --payload-file "$payload" \
    --output "$tx" \
    --ttl-seconds 600 >/dev/null
  local response
  response="$(broadcast_commit "$tx")"
  printf '%s\n' "$response" >"$ROOT/$transition_id.response.json"
  SUBMITTED_HEIGHT="$(printf '%s' "$response" | jq -er '.result.height | tonumber')"
  test "$SUBMITTED_ACTIVATION" -ge "$((SUBMITTED_HEIGHT + 2))"
  assert_committed_response "$response" "$SUBMITTED_HEIGHT"
  flush_mempools
}

CANONICAL_ACCOUNT_NONCE=0
submit_opaque() {
  local label="$1"
  local envelope_nonce="$2"
  CANONICAL_ACCOUNT_NONCE=$((CANONICAL_ACCOUNT_NONCE + 1))
  local account_nonce="$CANONICAL_ACCOUNT_NONCE"
  local current
  current="$(latest_height)"
  SUBMITTED_HEIGHT=$((current + 1))
  local payload="$ROOT/opaque-$label-$SUBMITTED_HEIGHT.bin"
  local tx="$ROOT/opaque-$label-$SUBMITTED_HEIGHT.tx.json"
  jq -n \
    --arg sender did:operator:1 \
    --arg account "fixture:lifecycle:$label:$SUBMITTED_HEIGHT" \
    --argjson nonce "$account_nonce" \
    '{schema:"trnm_canonical_tx_v1",sender:$sender,nonce:$nonce,max_gas:100000,fee_limit:"100000",command:{type:"credit_account",account:$account,amount:"1"}}' \
    >"$payload"
  "$CLI_BIN" sign \
    --private-key "$ROOT/operator.key" \
    --chain-id "$CHAIN_ID" \
    --command-id "lifecycle-$label-$SUBMITTED_HEIGHT" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$envelope_nonce" \
    --payload-type trnm.canonical.tx.v1 \
    --payload-file "$payload" \
    --output "$tx" \
    --ttl-seconds 600 >/dev/null
  local response
  response="$(broadcast_commit "$tx")"
  SUBMITTED_HEIGHT="$(printf '%s' "$response" | jq -er '.result.height | tonumber')"
  printf '%s\n' "$response" >"$ROOT/opaque-$label-$SUBMITTED_HEIGHT.response.json"
  assert_committed_response "$response" "$SUBMITTED_HEIGHT"
  flush_mempools
}

SETTLED_HEIGHT=0
drive_and_settle() {
  local target_height="$1"
  local label="$2"
  local nonce_base="$3"
  local current
  while true; do
    current="$(latest_height)"
    if (( current >= target_height )); then
      break
    fi
    submit_opaque "$label-$current" "$((nonce_base + current))"
  done
  SETTLED_HEIGHT="$(wait_settled_height_at_or_after "$target_height")"
}

assert_phase() {
  local label="$1"
  local height="$2"
  local expected_set="$3"
  local prefix
  prefix="$(printf '%03d-%s' "$height" "$label")"
  local index
  for index in 0 1 2 3 4 5; do
    wait_height "$index" "$height"
  done
  wait_app_hash_convergence "$height"
  for index in 0 1 2 3 4 5; do
    python3 "$HELPER" assert-phase \
      --label "$label" \
      --node "node$index" \
      --chain-id "$CHAIN_ID" \
      --rpc-url "http://127.0.0.1:$((BASE_RPC + index * 10))" \
      --height "$height" \
      --expected-set "$expected_set" \
      --state-path "$ROOT/node$index/app-state.json" \
      --json-out "$ROOT/evidence/phases/$prefix-node$index.json"
  done
  test "$(
    jq -r .app_hash_hex "$ROOT/evidence/phases/$prefix"-node*.json |
      sort -u | wc -l
  )" = "1"
  printf 'TRNM_COMETBFT_VALIDATOR_PHASE_OK label=%s height=%s validators=%s app_hash=%s\n' \
    "$label" \
    "$height" \
    "$(jq 'length' "$expected_set")" \
    "$(jq -r .app_hash_hex "$ROOT/evidence/phases/$prefix-node0.json")"
}

assert_local_power() {
  local index="$1"
  local expected="$2"
  local power
  for _ in $(seq 1 120); do
    power="$(
      curl -fsS "http://127.0.0.1:$((BASE_RPC + index * 10))/status" 2>/dev/null |
        jq -r '.result.validator_info.voting_power' || true
    )"
    if [[ "$power" = "$expected" ]]; then
      return 0
    fi
    sleep 0.25
  done
  printf 'validator power mismatch node=%s expected=%s observed=%s\n' \
    "$index" "$expected" "$power" >&2
  return 1
}

for index in 0 1 2 3 4 5; do
  start_app "$index"
done
for index in 0 1 2 3 4 5; do
  start_comet "$index"
done
for index in 0 1 2 3 4 5; do
  wait_rpc "$index"
done
for index in 0 1 2 3 4 5; do
  wait_peers "$index" 3
done
initial_height=1
for index in 0 1 2 3 4 5; do
  wait_height "$index" "$initial_height"
done
wait_app_hash_convergence "$initial_height"

submit_transition \
  add-node4 1 \
  "$ROOT/validator-set-initial-4.json" \
  "$ROOT/validator-set-added-5.json" \
  "$ROOT/node4/config/priv_validator_key.json"
add_height="$SUBMITTED_HEIGHT"
add_activation="$SUBMITTED_ACTIVATION"
drive_and_settle "$add_activation" add-advance 1000
add_active_height="$SETTLED_HEIGHT"
assert_phase add-active "$add_active_height" "$ROOT/validator-set-added-5.json"
assert_local_power 4 10

submit_transition \
  remove-node0 2 \
  "$ROOT/validator-set-added-5.json" \
  "$ROOT/validator-set-removed-4.json"
remove_height="$SUBMITTED_HEIGHT"
remove_activation="$SUBMITTED_ACTIVATION"
drive_and_settle "$remove_activation" remove-advance 2000
remove_active_height="$SETTLED_HEIGHT"
assert_phase remove-active "$remove_active_height" "$ROOT/validator-set-removed-4.json"
assert_local_power 0 0

submit_transition \
  rotate-node1-to-node5 3 \
  "$ROOT/validator-set-removed-4.json" \
  "$ROOT/validator-set-rotated-4.json" \
  "$ROOT/node5/config/priv_validator_key.json"
rotation_height="$SUBMITTED_HEIGHT"
rotation_activation="$SUBMITTED_ACTIVATION"
drive_and_settle "$rotation_activation" rotation-advance 3000
rotation_active_height="$SETTLED_HEIGHT"
assert_phase rotation-active "$rotation_active_height" "$ROOT/validator-set-rotated-4.json"
assert_local_power 1 0
assert_local_power 5 10

submit_opaque rotated-set-continues 4000
final_height="$(wait_settled_height_at_or_after "$SUBMITTED_HEIGHT")"
assert_phase rotated-set-continues "$final_height" "$ROOT/validator-set-rotated-4.json"

jq -s \
  '{
    schema:"trnm_validator_lifecycle_fixture_evidence_v1",
    status:"PASS",
    phases:.
  }' \
  "$ROOT/evidence/phases/"*.json >"$ROOT/evidence/validator-lifecycle-phases.json"

safety_args=(
  --expected-chain-id "$CHAIN_ID"
  --json-out "$ROOT/evidence/safety-evidence.json"
  --tsv-out "$ROOT/evidence/safety-evidence.tsv"
)
for index in 0 1 2 3 4 5; do
  safety_args+=(--history-node "node$index")
  safety_args+=(
    --node "node$index"
    "http://127.0.0.1:$((BASE_RPC + index * 10))"
    "$ROOT/node$index/app-state.json"
  )
done
python3 "$SCRIPT_DIR/assert_cometbft_safety.py" "${safety_args[@]}"
test "$(jq -er .status "$ROOT/evidence/safety-evidence.json")" = "PASS"
test "$(jq -er .common_tip_height "$ROOT/evidence/safety-evidence.json")" = "$final_height"
final_app_hash="$(jq -er .app_hash_hex "$ROOT/node5/app-state.json")"

printf 'TRNM_COMETBFT_VALIDATOR_LIFECYCLE_OK cometbft=%s add=%s->%s remove=%s->%s rotate=%s->%s final_height=%s validators=4 safety_evidence=verified app_hash=%s root=%s\n' \
  "$EXPECTED_COMETBFT_VERSION" \
  "$add_height" "$add_activation" \
  "$remove_height" "$remove_activation" \
  "$rotation_height" "$rotation_activation" \
  "$final_height" "$final_app_hash" "$ROOT"
