#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."

COMETBFT_BIN="${TRNM_COMETBFT_BIN:-cometbft}"
APP_VERSION="${TRNM_COMETBFT_APP_VERSION:-6}"
APP_CONFIG_SCHEMA="${TRNM_COMETBFT_APP_CONFIG_SCHEMA:-trnm_cometbft_app_config_v1}"
GENESIS_SCHEMA="${TRNM_COMETBFT_GENESIS_SCHEMA:-trnm_cometbft_genesis_v3}"
VALIDATOR_GOVERNANCE_SCHEMA="${TRNM_COMETBFT_VALIDATOR_GOVERNANCE_SCHEMA:-trnm_validator_governance_v1}"
MIN_ACTIVATION_DELAY_BLOCKS="${TRNM_COMETBFT_MIN_ACTIVATION_DELAY_BLOCKS:-2}"
CHAIN_ID="${TRNM_COMETBFT_PARTITION_CHAIN_ID:-trnm-comet-partition}"
CASE="${TRNM_COMETBFT_PARTITION_CASE:-3-1}"
KEEP="${TRNM_COMETBFT_PARTITION_KEEP:-0}"
CLEAN_ON_SUCCESS="${TRNM_COMETBFT_PARTITION_CLEAN_ON_SUCCESS:-}"
STALL_SECONDS="${TRNM_COMETBFT_PARTITION_STALL_SECONDS:-8}"
QUIESCENCE_SECONDS="${TRNM_COMETBFT_PARTITION_QUIESCENCE_SECONDS:-3}"
APP_PIDS=("" "" "" "")
COMET_PIDS=("" "" "" "")
PROXY_PID=""
ROOT_CREATED_BY_SCRIPT=0
ROOT_MARKER_NAME=".trnm-comet-partition-root-v1"
ROOT_MARKER_VALUE="trnm-comet-partition-root-v1"

LINK_NAMES=("0-1" "0-2" "0-3" "1-2" "1-3" "2-3")
LINK_LOW=(0 0 0 1 1 2)
LINK_HIGH=(1 2 3 2 3 3)

if [[ ! "$APP_VERSION" =~ ^[1-9][0-9]*$ ]]; then
  printf 'TRNM_COMETBFT_PARTITION_FAILED reason=invalid_app_version value=%s\n' \
    "$APP_VERSION" >&2
  exit 2
fi
if [[ ! "$MIN_ACTIVATION_DELAY_BLOCKS" =~ ^[0-9]+$ ]] ||
  ((MIN_ACTIVATION_DELAY_BLOCKS < 2)); then
  printf 'TRNM_COMETBFT_PARTITION_FAILED reason=invalid_min_activation_delay value=%s\n' \
    "$MIN_ACTIVATION_DELAY_BLOCKS" >&2
  exit 2
fi
if [[ ! "$STALL_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  printf 'TRNM_COMETBFT_PARTITION_FAILED reason=invalid_stall_seconds value=%s\n' \
    "$STALL_SECONDS" >&2
  exit 2
fi
if [[ ! "$QUIESCENCE_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
  printf 'TRNM_COMETBFT_PARTITION_FAILED reason=invalid_quiescence_seconds value=%s\n' \
    "$QUIESCENCE_SECONDS" >&2
  exit 2
fi
if [[ "$CASE" != "3-1" && "$CASE" != "2-2" ]]; then
  printf 'TRNM_COMETBFT_PARTITION_FAILED reason=invalid_case value=%s\n' \
    "$CASE" >&2
  exit 2
fi

select_base_port() {
  python3 - <<'PY'
import random
import socket

offsets = list(range(0, 4))
offsets += list(range(10, 14))
offsets += list(range(20, 24))
offsets += list(range(30, 36))
offsets += list(range(40, 44))
offsets += [50]
candidates = list(range(22000, 59000, 64))
random.SystemRandom().shuffle(candidates)
for base in candidates:
    sockets = []
    try:
        for offset in offsets:
            sock = socket.socket()
            sock.bind(("127.0.0.1", base + offset))
            sockets.append(sock)
    except OSError:
        pass
    else:
        print(base)
        raise SystemExit(0)
    finally:
        for sock in sockets:
            sock.close()
raise SystemExit("no free local port block found")
PY
}

if [[ -n "${TRNM_COMETBFT_PARTITION_BASE_PORT:-}" ]]; then
  BASE_PORT="$TRNM_COMETBFT_PARTITION_BASE_PORT"
else
  BASE_PORT="$(select_base_port)"
fi
if [[ ! "$BASE_PORT" =~ ^[0-9]+$ ]] || ((BASE_PORT < 1024 || BASE_PORT > 65400)); then
  printf 'TRNM_COMETBFT_PARTITION_FAILED reason=invalid_base_port value=%s\n' \
    "$BASE_PORT" >&2
  exit 2
fi

rpc_port() {
  printf '%s\n' $((BASE_PORT + $1))
}

p2p_port() {
  printf '%s\n' $((BASE_PORT + 10 + $1))
}

abci_port() {
  printf '%s\n' $((BASE_PORT + 20 + $1))
}

proxy_port() {
  printf '%s\n' $((BASE_PORT + 30 + $1))
}

dead_advertise_port() {
  printf '%s\n' $((BASE_PORT + 40 + $1))
}

CONTROL_PORT=$((BASE_PORT + 50))

if [[ -n "${TRNM_COMETBFT_PARTITION_ROOT:-}" ]]; then
  ROOT="$TRNM_COMETBFT_PARTITION_ROOT"
  if [[ ! -e "$ROOT" ]]; then
    mkdir -p -- "$ROOT"
    ROOT_CREATED_BY_SCRIPT=1
  elif [[ ! -d "$ROOT" || -L "$ROOT" ]]; then
    printf 'TRNM_COMETBFT_PARTITION_FAILED reason=root_is_not_directory root=%s\n' \
      "$ROOT" >&2
    exit 2
  elif [[ -n "$(find "$ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    printf 'TRNM_COMETBFT_PARTITION_FAILED reason=root_is_not_empty root=%s\n' \
      "$ROOT" >&2
    exit 2
  fi
  CLEAN_ON_SUCCESS="${CLEAN_ON_SUCCESS:-0}"
else
  ROOT="$(mktemp -d /tmp/trnm-comet-partition.XXXXXX)"
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
  [[ "$base" == trnm-comet-partition.* || "$base" == trnm-comet-partition-* ]]
}

proxy_control() {
  python3 "$SCRIPT_DIR/p2p_fault_proxy.py" control \
    --control-port "$CONTROL_PORT" \
    "$@"
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
  if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    proxy_control shutdown >>"$ROOT/proxy-control.log" 2>&1 || \
      kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [[ "$status" == "0" && "$KEEP" != "1" && "$CLEAN_ON_SUCCESS" == "1" ]]; then
    if safe_to_remove_root; then
      rm -rf -- "$ROOT"
    else
      printf 'TRNM_COMETBFT_PARTITION_ROOT_PRESERVED reason=cleanup_safety_check_failed root=%s\n' \
        "$ROOT" >&2
    fi
  else
    printf 'TRNM_COMETBFT_PARTITION_ROOT_PRESERVED status=%s root=%s\n' \
      "$status" "$ROOT" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'printf "TRNM_COMETBFT_PARTITION_FAILED line=%s root=%s\n" "$LINENO" "$ROOT" >&2' ERR

command -v "$COMETBFT_BIN" >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
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

mkdir -p -- "$ROOT/evidence"
key_json="$("$CLI_BIN" keygen --output "$ROOT/operator.key")"
public_key="$(printf '%s' "$key_json" | jq -r .public_key_hex)"
test -n "$public_key"

for index in 0 1 2 3; do
  home="$ROOT/node$index"
  "$COMETBFT_BIN" init --home "$home" >/dev/null
  python3 - "$home/config/config.toml" "$(dead_advertise_port "$index")" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
dead_port = sys.argv[2]
text = path.read_text(encoding="utf-8")
old_duplicate = "allow_duplicate_ip = false"
old_external = 'external_address = ""'
if text.count(old_duplicate) != 1 or text.count(old_external) != 1:
    raise SystemExit("unexpected CometBFT P2P config shape")
text = text.replace(old_duplicate, "allow_duplicate_ip = true", 1)
text = text.replace(
    old_external,
    f'external_address = "tcp://127.0.0.1:{dead_port}"',
    1,
)
path.write_text(text, encoding="utf-8")
PY
  jq -n \
    --arg schema "$APP_CONFIG_SCHEMA" \
    --arg chain_id "$CHAIN_ID" \
    --arg public_key "$public_key" \
    --arg state_path "$home/app-state.json" \
    '{
      schema:$schema,
      chain_id:$chain_id,
      authorized_signers:[{
        signer_id:"did:operator:1",
        signer_role:"operator",
        public_key_hex:$public_key
      }],
      state_path:$state_path
    }' >"$home/app.json"
done

validators="$(
  for index in 0 1 2 3; do
    jq '.validators[0]' "$ROOT/node$index/config/genesis.json"
  done | jq -s '.'
)"
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
jq \
  --arg chain_id "$CHAIN_ID" \
  --arg genesis_schema "$GENESIS_SCHEMA" \
  --arg governance_schema "$VALIDATOR_GOVERNANCE_SCHEMA" \
  --arg public_key "$public_key" \
  --arg app_version_string "$APP_VERSION" \
  --argjson app_version "$APP_VERSION" \
  --argjson min_activation_delay_blocks "$MIN_ACTIVATION_DELAY_BLOCKS" \
  --argjson validators "$validators" \
  --argjson initial_validators "$initial_validators" \
  '.chain_id=$chain_id
   | .validators=$validators
   | .consensus_params.version.app=$app_version_string
   | .app_state={
       schema:$genesis_schema,
       chain_id:$chain_id,
       app_version:$app_version,
       authorized_signers:[{
         signer_id:"did:operator:1",
         signer_role:"operator",
         public_key_hex:$public_key
       }],
       research_authorities:{
         nakama_authorities:[],
         hepta_authorities:[]
       },
       validator_governance:{
         schema:$governance_schema,
         signer_id:"did:operator:1",
         min_activation_delay_blocks:$min_activation_delay_blocks,
         unsafe_allow_single_validator_genesis:false
       },
       initial_validators:$initial_validators
     }' \
  "$ROOT/node0/config/genesis.json" >"$ROOT/genesis.json"
for index in 0 1 2 3; do
  cp "$ROOT/genesis.json" "$ROOT/node$index/config/genesis.json"
done

node_ids=()
for index in 0 1 2 3; do
  node_ids+=("$("$COMETBFT_BIN" show-node-id --home "$ROOT/node$index")")
done

python3 - "$ROOT/proxy-config.json" "$BASE_PORT" <<'PY'
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
base = int(sys.argv[2])
pairs = ((0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3))
payload = {
    "links": [
        {
            "name": f"{low}-{high}",
            "listen_host": "127.0.0.1",
            "listen_port": base + 30 + index,
            "target_host": "127.0.0.1",
            "target_port": base + 10 + high,
        }
        for index, (low, high) in enumerate(pairs)
    ]
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "$SCRIPT_DIR/p2p_fault_proxy.py" serve \
  --config "$ROOT/proxy-config.json" \
  --control-port "$CONTROL_PORT" \
  >"$ROOT/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 100); do
  if proxy_control status >>"$ROOT/proxy-control.log" 2>&1; then
    break
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    printf 'P2P fault proxy exited before readiness\n' >&2
    exit 1
  fi
  sleep 0.1
done
proxy_control status >>"$ROOT/proxy-control.log"

start_app() {
  local index="$1"
  "$APP_BIN" \
    --config "$ROOT/node$index/app.json" \
    --listen-addr "127.0.0.1:$(abci_port "$index")" \
    >"$ROOT/node$index/app.log" 2>&1 &
  APP_PIDS[index]=$!
}

start_comet() {
  local index="$1"
  local peers=()
  local link_index
  local high
  for link_index in "${!LINK_NAMES[@]}"; do
    if [[ "${LINK_LOW[$link_index]}" == "$index" ]]; then
      high="${LINK_HIGH[$link_index]}"
      peers+=("${node_ids[$high]}@127.0.0.1:$(proxy_port "$link_index")")
    fi
  done
  local peer_csv
  peer_csv="$(IFS=,; echo "${peers[*]}")"
  "$COMETBFT_BIN" start \
    --home "$ROOT/node$index" \
    --proxy_app "tcp://127.0.0.1:$(abci_port "$index")" \
    --rpc.laddr "tcp://127.0.0.1:$(rpc_port "$index")" \
    --p2p.laddr "tcp://127.0.0.1:$(p2p_port "$index")" \
    --p2p.persistent_peers "$peer_csv" \
    --p2p.pex=false \
    --consensus.create_empty_blocks=false \
    >"$ROOT/node$index/comet.log" 2>&1 &
  COMET_PIDS[index]=$!
}

wait_rpc() {
  local index="$1"
  for _ in $(seq 1 200); do
    if curl -fsS "http://127.0.0.1:$(rpc_port "$index")/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

peer_ids() {
  local index="$1"
  curl -fsS "http://127.0.0.1:$(rpc_port "$index")/net_info" |
    jq -r '.result.peers[]?.node_info.id' |
    sort |
    paste -sd, -
}

wait_peer_set() {
  local index="$1"
  shift
  local expected_ids=()
  local expected
  local actual=""
  local peer
  for peer in "$@"; do
    expected_ids+=("${node_ids[$peer]}")
  done
  expected="$(printf '%s\n' "${expected_ids[@]}" | sed '/^$/d' | sort | paste -sd, -)"
  for _ in $(seq 1 240); do
    actual="$(peer_ids "$index" 2>/dev/null || true)"
    if [[ "$actual" == "$expected" ]]; then
      return 0
    fi
    sleep 0.25
  done
  printf 'peer set mismatch node=%s expected=%s actual=%s\n' \
    "$index" "$expected" "$actual" >&2
  return 1
}

wait_full_mesh() {
  wait_peer_set 0 1 2 3
  wait_peer_set 1 0 2 3
  wait_peer_set 2 0 1 3
  wait_peer_set 3 0 1 2
}

status_height() {
  local index="$1"
  curl -fsS "http://127.0.0.1:$(rpc_port "$index")/status" |
    jq -r '.result.sync_info.latest_block_height | tonumber'
}

local_height() {
  local index="$1"
  jq -r '.height | tonumber' "$ROOT/node$index/app-state.json"
}

terminal_observation() {
  local index="$1"
  local comet_height
  local abci_height
  local app_height
  local app_hash
  comet_height="$(status_height "$index")"
  abci_height="$(
    curl -fsS "http://127.0.0.1:$(rpc_port "$index")/abci_info" |
      jq -r '(.result.response.last_block_height // "0") | tonumber'
  )"
  app_height="$(local_height "$index")"
  app_hash="$(jq -r '.app_hash_hex' "$ROOT/node$index/app-state.json")"
  [[ "$comet_height" =~ ^[0-9]+$ ]]
  [[ "$abci_height" =~ ^[0-9]+$ ]]
  [[ "$app_height" =~ ^[0-9]+$ ]]
  [[ "$app_hash" =~ ^[0-9a-f]{64}$ ]]
  test "$comet_height" = "$abci_height"
  test "$comet_height" = "$app_height"
  printf '%s:%s\n' "$comet_height" "$app_hash"
}

wait_height() {
  local index="$1"
  local expected="$2"
  local height=""
  for _ in $(seq 1 240); do
    height="$(status_height "$index" 2>/dev/null || true)"
    if [[ "$height" =~ ^[0-9]+$ ]] && ((height >= expected)); then
      return 0
    fi
    sleep 0.25
  done
  printf 'height wait timed out node=%s expected=%s actual=%s\n' \
    "$index" "$expected" "$height" >&2
  return 1
}

wait_common_quiescence() {
  local indexes=("$@")
  local required_checks=$((QUIESCENCE_SECONDS * 4))
  local stable_checks=0
  local last_observation=""
  local current_observation=""
  local observation
  local observations=()
  local index
  local valid
  for _ in $(seq 1 480); do
    observations=()
    valid=1
    for index in "${indexes[@]}"; do
      if observation="$(terminal_observation "$index" 2>/dev/null)"; then
        observations+=("$observation")
      else
        valid=0
        break
      fi
    done
    if [[ "$valid" == "1" ]] &&
      [[ "$(printf '%s\n' "${observations[@]}" | sort -u | wc -l)" == "1" ]]; then
      current_observation="${observations[0]}"
      if [[ "$current_observation" == "$last_observation" ]]; then
        stable_checks=$((stable_checks + 1))
      else
        last_observation="$current_observation"
        stable_checks=1
      fi
      if ((stable_checks >= required_checks)); then
        printf '%s\n' "${current_observation%%:*}"
        return 0
      fi
    else
      stable_checks=0
      last_observation=""
    fi
    sleep 0.25
  done
  printf 'common quiescence timed out nodes=%s last=%s\n' \
    "${indexes[*]}" "$last_observation" >&2
  return 1
}

wait_app_hash_convergence() {
  local indexes=("$@")
  local observations=()
  local index
  for _ in $(seq 1 240); do
    observations=()
    for index in "${indexes[@]}"; do
      if [[ ! -f "$ROOT/node$index/app-state.json" ]]; then
        observations+=("missing-$index")
      else
        observations+=("$(
          jq -r '(.height | tostring) + ":" + .app_hash_hex' \
            "$ROOT/node$index/app-state.json"
        )")
      fi
    done
    if [[ "$(printf '%s\n' "${observations[@]}" | sort -u | wc -l)" == "1" ]]; then
      return 0
    fi
    sleep 0.25
  done
  printf 'app state convergence timed out: %s\n' "${observations[*]}" >&2
  return 1
}

assert_terminal_height() {
  local index="$1"
  local expected="$2"
  local observation
  observation="$(terminal_observation "$index")"
  test "${observation%%:*}" = "$expected"
}

wait_proxy_links_active() {
  local response=""
  local link
  local active
  local all_active
  for _ in $(seq 1 120); do
    response="$(proxy_control status)"
    all_active=1
    for link in "$@"; do
      active="$(
        printf '%s' "$response" |
          jq -r --arg link "$link" \
            '.links[] | select(.name == $link) | .active_connections'
      )"
      if [[ ! "$active" =~ ^[1-9][0-9]*$ ]]; then
        all_active=0
        break
      fi
    done
    if [[ "$all_active" == "1" ]]; then
      printf '%s\n' "$response" >>"$ROOT/proxy-control.log"
      printf '%s\n' "$response" >"$ROOT/evidence/proxy-before-cut.json"
      return 0
    fi
    sleep 0.25
  done
  printf '%s\n' "$response" >>"$ROOT/proxy-control.log"
  printf 'proxy links never became active links=%s\n' "$*" >&2
  return 1
}

set_proxy_links() {
  local action="$1"
  shift
  local response
  local link
  response="$(proxy_control "$action" "$@")"
  printf '%s\n' "$response" >>"$ROOT/proxy-control.log"
  for link in "$@"; do
    test "$(
      printf '%s' "$response" |
        jq -r --arg link "$link" '.links[] | select(.name == $link) | .enabled'
    )" = "$([[ "$action" == "enable" ]] && printf true || printf false)"
    if [[ "$action" == "disable" ]]; then
      test "$(
        printf '%s' "$response" |
          jq -r --arg link "$link" \
            '.links[] | select(.name == $link) | .active_connections'
      )" = "0"
    fi
  done
}

sign_tx() {
  local nonce="$1"
  local command_id="$2"
  local label="$3"
  local payload="$ROOT/payload-$label.bin"
  local output="$ROOT/tx-$label.json"
  jq -n \
    --arg sender did:operator:1 \
    --arg account "fixture:partition:$label" \
    --argjson nonce "$nonce" \
    '{schema:"trnm_canonical_tx_v1",sender:$sender,nonce:$nonce,max_gas:100000,fee_limit:"100000",command:{type:"credit_account",account:$account,amount:"1"}}' \
    >"$payload"
  "$CLI_BIN" sign \
    --private-key "$ROOT/operator.key" \
    --chain-id "$CHAIN_ID" \
    --command-id "$command_id" \
    --signer-id did:operator:1 \
    --signer-role operator \
    --nonce "$nonce" \
    --payload-type trnm.canonical.tx.v1 \
    --payload-file "$payload" \
    --output "$output" >/dev/null
  printf '%s\n' "$output"
}

encoded_tx() {
  python3 - "$1" <<'PY'
import base64
from pathlib import Path
import sys

print(base64.b64encode(Path(sys.argv[1]).read_bytes()).decode("ascii"))
PY
}

broadcast_commit() {
  local index="$1"
  local tx_file="$2"
  local tx_b64
  tx_b64="$(encoded_tx "$tx_file")"
  curl -fsS --max-time 90 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_commit\",\"params\":{\"tx\":\"$tx_b64\"}}" \
    "http://127.0.0.1:$(rpc_port "$index")"
}

broadcast_sync() {
  local index="$1"
  local tx_file="$2"
  local tx_b64
  tx_b64="$(encoded_tx "$tx_file")"
  curl -fsS --max-time 10 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"broadcast_tx_sync\",\"params\":{\"tx\":\"$tx_b64\"}}" \
    "http://127.0.0.1:$(rpc_port "$index")"
}

assert_commit_success() {
  local response="$1"
  test "$(printf '%s' "$response" | jq -r '.result.check_tx.code | tonumber')" = "0"
  test "$(printf '%s' "$response" | jq -r '.result.tx_result.code | tonumber')" = "0"
}

run_safety_evidence() {
  local label="$1"
  shift
  local indexes=("$@")
  local args=(
    python3 "$SCRIPT_DIR/assert_cometbft_safety.py"
    --expected-chain-id "$CHAIN_ID"
    --json-out "$ROOT/evidence/$label.json"
    --tsv-out "$ROOT/evidence/$label.tsv"
  )
  local index
  for index in "${indexes[@]}"; do
    args+=(--history-node "node$index")
  done
  for index in "${indexes[@]}"; do
    args+=(
      --node "node$index"
      "http://127.0.0.1:$(rpc_port "$index")"
      "$ROOT/node$index/app-state.json"
    )
  done
  "${args[@]}" | tee -a "$ROOT/evidence/safety-markers.log"
}

record_conflict_counts() {
  local start_height="$1"
  local end_height="$2"
  local first_id="$3"
  local second_id="$4"
  local output="$5"
  python3 - \
    "http://127.0.0.1:$(rpc_port 0)" \
    "$start_height" "$end_height" "$first_id" "$second_id" "$output" <<'PY'
import base64
import json
from pathlib import Path
import os
import sys
from urllib.parse import urlencode
from urllib.request import urlopen

rpc, start_text, end_text, first_id, second_id, output_text = sys.argv[1:]
start = int(start_text)
end = int(end_text)
counts = {first_id: 0, second_id: 0}
heights = {first_id: [], second_id: []}
for height in range(start, end + 1):
    url = f"{rpc}/block?{urlencode({'height': height})}"
    with urlopen(url, timeout=3.0) as response:
        payload = json.load(response)
    for encoded in payload["result"]["block"]["data"].get("txs") or []:
        envelope = json.loads(base64.b64decode(encoded, validate=True))
        command_id = envelope.get("command_id")
        if command_id in counts:
            counts[command_id] += 1
            heights[command_id].append(height)
evidence = {
    "schema": "trnm_cometbft_conflict_evidence_v1",
    "height_range": {"start": start, "end": end},
    "commands": {
        command_id: {"count": counts[command_id], "heights": heights[command_id]}
        for command_id in sorted(counts)
    },
    "total_conflicting_commands_committed": sum(counts.values()),
}
output = Path(output_text)
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
temporary.write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
os.replace(temporary, output)
print(json.dumps(evidence, sort_keys=True))
PY
}

record_mempool_evidence() {
  local index="$1"
  local expected_hash="$2"
  local output="$3"
  python3 - \
    "http://127.0.0.1:$(rpc_port "$index")" \
    "$index" "$expected_hash" "$output" <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from urllib.request import urlopen

rpc, index_text, expected_hash, output_text = sys.argv[1:]
expected_hash = expected_hash.lower()
observed_hashes = []
reported_count = 0
for _ in range(50):
    with urlopen(f"{rpc}/unconfirmed_txs?limit=100", timeout=3.0) as response:
        payload = json.load(response)
    result = payload["result"]
    encoded_txs = result.get("txs") or []
    observed_hashes = sorted(
        hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest()
        for encoded in encoded_txs
    )
    reported_count = int(result.get("n_txs") or 0)
    if expected_hash in observed_hashes:
        break
    time.sleep(0.1)
present = expected_hash in observed_hashes
evidence = {
    "schema": "trnm_cometbft_mempool_evidence_v1",
    "node_index": int(index_text),
    "expected_tx_hash": expected_hash,
    "expected_present": present,
    "reported_count": reported_count,
    "observed_tx_hashes": observed_hashes,
}
output = Path(output_text)
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
temporary.write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
os.replace(temporary, output)
print(json.dumps(evidence, sort_keys=True))
if not present:
    raise SystemExit("expected transaction is absent from the pre-heal mempool")
PY
}

for index in 0 1 2 3; do
  start_app "$index"
done
for index in 0 1 2 3; do
  start_comet "$index"
done
for index in 0 1 2 3; do
  wait_rpc "$index"
done
wait_full_mesh
wait_height 0 1
wait_app_hash_convergence 0 1 2 3

if [[ "$CASE" == "3-1" ]]; then
  wait_proxy_links_active 0-3 1-3 2-3
  set_proxy_links disable 0-3 1-3 2-3
  wait_peer_set 0 1 2
  wait_peer_set 1 0 2
  wait_peer_set 2 0 1
  wait_peer_set 3
  isolated_height="$(wait_common_quiescence 3)"
  majority_start_height="$(local_height 0)"

  majority_tx="$(sign_tx 1 command-partition-majority majority)"
  majority_response="$(broadcast_commit 0 "$majority_tx")"
  assert_commit_success "$majority_response"
  majority_height="$(printf '%s' "$majority_response" | jq -r '.result.height | tonumber')"
  for index in 0 1 2; do
    wait_height "$index" "$majority_height"
  done
  wait_app_hash_convergence 0 1 2
  for _ in $(seq 1 $((STALL_SECONDS * 4))); do
    assert_terminal_height 3 "$isolated_height"
    sleep 0.25
  done
  wait_peer_set 3
  majority_end_height="$(local_height 0)"
  ((majority_end_height > isolated_height))
  ((majority_end_height > majority_start_height))
  proxy_control status >"$ROOT/evidence/partition-3-1-proxy-during.json"
  node0_peers="$(peer_ids 0)"
  node1_peers="$(peer_ids 1)"
  node2_peers="$(peer_ids 2)"
  node3_peers="$(peer_ids 3)"
  jq -n \
    --argjson isolated_height "$isolated_height" \
    --argjson majority_start_height "$majority_start_height" \
    --argjson majority_end_height "$majority_end_height" \
    --argjson stall_seconds "$STALL_SECONDS" \
    --arg node0_peers "$node0_peers" \
    --arg node1_peers "$node1_peers" \
    --arg node2_peers "$node2_peers" \
    --arg node3_peers "$node3_peers" \
    --slurpfile proxy "$ROOT/evidence/partition-3-1-proxy-during.json" \
    '{
      schema:"trnm_cometbft_partition_stall_evidence_v1",
      case:"3-1",
      stall_seconds:$stall_seconds,
      isolated_height_start:$isolated_height,
      isolated_height_end:$isolated_height,
      majority_height_start:$majority_start_height,
      majority_height_end:$majority_end_height,
      peer_ids:{
        node0:($node0_peers | split(",") | map(select(length > 0))),
        node1:($node1_peers | split(",") | map(select(length > 0))),
        node2:($node2_peers | split(",") | map(select(length > 0))),
        node3:($node3_peers | split(",") | map(select(length > 0)))
      },
      proxy:$proxy[0]
    }' >"$ROOT/evidence/partition-3-1-stalled.json"
  run_safety_evidence partition-3-1-majority 0 1 2

  set_proxy_links enable 0-3 1-3 2-3
  wait_full_mesh
  wait_height 3 "$majority_height"
  wait_app_hash_convergence 0 1 2 3

  post_three_one_tx="$(sign_tx 2 command-partition-after-3-1 after-3-1)"
  post_three_one_response="$(broadcast_commit 0 "$post_three_one_tx")"
  assert_commit_success "$post_three_one_response"
  post_three_one_height="$(
    printf '%s' "$post_three_one_response" | jq -r '.result.height | tonumber'
  )"
  for index in 0 1 2 3; do
    wait_height "$index" "$post_three_one_height"
  done
  wait_app_hash_convergence 0 1 2 3
  run_safety_evidence partition-3-1-healed 0 1 2 3
  final_height="$(
    jq -r '.common_tip_height | tonumber' \
      "$ROOT/evidence/partition-3-1-healed.json"
  )"
  final_hash="$(
    jq -r '.nodes[0].local_app_hash' \
      "$ROOT/evidence/partition-3-1-healed.json"
  )"
  printf 'TRNM_COMETBFT_PARTITION_CASE_OK case=3-1 active_proxy_cut=verified majority_progress=verified isolated_stall=verified heal=verified post_heal_liveness=verified\n'
else
  wait_proxy_links_active 0-2 0-3 1-2 1-3
  set_proxy_links disable 0-2 0-3 1-2 1-3
  wait_peer_set 0 1
  wait_peer_set 1 0
  wait_peer_set 2 3
  wait_peer_set 3 2
  partition_height="$(wait_common_quiescence 0 1 2 3)"
  for index in 0 1 2 3; do
    assert_terminal_height "$index" "$partition_height"
  done

  conflict_a_id="command-partition-2-2-a"
  conflict_b_id="command-partition-2-2-b"
  conflict_a_tx="$(sign_tx 1 "$conflict_a_id" conflict-a)"
  conflict_b_tx="$(sign_tx 1 "$conflict_b_id" conflict-b)"
  conflict_a_response="$(broadcast_sync 0 "$conflict_a_tx")"
  conflict_b_response="$(broadcast_sync 2 "$conflict_b_tx")"
  test "$(printf '%s' "$conflict_a_response" | jq -r '.result.code | tonumber')" = "0"
  test "$(printf '%s' "$conflict_b_response" | jq -r '.result.code | tonumber')" = "0"
  printf '%s\n' "$conflict_a_response" |
    jq '{jsonrpc,id,result:{code:.result.code,hash:.result.hash,log:.result.log}}' \
      >"$ROOT/evidence/partition-2-2-broadcast-a.json"
  printf '%s\n' "$conflict_b_response" |
    jq '{jsonrpc,id,result:{code:.result.code,hash:.result.hash,log:.result.log}}' \
      >"$ROOT/evidence/partition-2-2-broadcast-b.json"
  conflict_a_hash="$(
    printf '%s' "$conflict_a_response" | jq -r '.result.hash | ascii_downcase'
  )"
  conflict_b_hash="$(
    printf '%s' "$conflict_b_response" | jq -r '.result.hash | ascii_downcase'
  )"

  stall_checks=$((STALL_SECONDS * 4))
  for _ in $(seq 1 "$stall_checks"); do
    for index in 0 1 2 3; do
      assert_terminal_height "$index" "$partition_height"
    done
    sleep 0.25
  done
  wait_peer_set 0 1
  wait_peer_set 1 0
  wait_peer_set 2 3
  wait_peer_set 3 2
  record_mempool_evidence \
    0 "$conflict_a_hash" \
    "$ROOT/evidence/partition-2-2-mempool-left.json" \
    >"$ROOT/evidence/partition-2-2-mempool-left.log"
  record_mempool_evidence \
    2 "$conflict_b_hash" \
    "$ROOT/evidence/partition-2-2-mempool-right.json" \
    >"$ROOT/evidence/partition-2-2-mempool-right.log"
  proxy_control status >"$ROOT/evidence/partition-2-2-proxy-during.json"
  node0_peers="$(peer_ids 0)"
  node1_peers="$(peer_ids 1)"
  node2_peers="$(peer_ids 2)"
  node3_peers="$(peer_ids 3)"
  jq -n \
    --argjson partition_height "$partition_height" \
    --argjson stall_seconds "$STALL_SECONDS" \
    --arg node0_peers "$node0_peers" \
    --arg node1_peers "$node1_peers" \
    --arg node2_peers "$node2_peers" \
    --arg node3_peers "$node3_peers" \
    --slurpfile proxy "$ROOT/evidence/partition-2-2-proxy-during.json" \
    '{
      schema:"trnm_cometbft_partition_stall_evidence_v1",
      case:"2-2",
      start_height:$partition_height,
      end_height:$partition_height,
      stall_seconds:$stall_seconds,
      left_partition:[0,1],
      right_partition:[2,3],
      committed_blocks_during_partition:0,
      peer_ids:{
        node0:($node0_peers | split(",") | map(select(length > 0))),
        node1:($node1_peers | split(",") | map(select(length > 0))),
        node2:($node2_peers | split(",") | map(select(length > 0))),
        node3:($node3_peers | split(",") | map(select(length > 0)))
      },
      proxy:$proxy[0]
    }' >"$ROOT/evidence/partition-2-2-stalled.json"

  set_proxy_links enable 0-2 0-3 1-2 1-3
  wait_full_mesh
  wait_height 0 "$((partition_height + 1))"
  two_two_commit_height="$(status_height 0)"
  for index in 0 1 2 3; do
    wait_height "$index" "$two_two_commit_height"
  done
  wait_app_hash_convergence 0 1 2 3
  two_two_commit_height="$(local_height 0)"

  record_conflict_counts \
    "$((partition_height + 1))" \
    "$two_two_commit_height" \
    "$conflict_a_id" \
    "$conflict_b_id" \
    "$ROOT/evidence/partition-2-2-conflicts-after-heal.json" \
    >"$ROOT/evidence/partition-2-2-conflicts-after-heal.log"
  test "$(
    jq -r '.total_conflicting_commands_committed' \
      "$ROOT/evidence/partition-2-2-conflicts-after-heal.json"
  )" = "1"

  post_two_two_tx="$(sign_tx 2 command-partition-after-2-2 after-2-2)"
  post_two_two_response="$(broadcast_commit 0 "$post_two_two_tx")"
  assert_commit_success "$post_two_two_response"
  post_two_two_height="$(
    printf '%s' "$post_two_two_response" | jq -r '.result.height | tonumber'
  )"
  for index in 0 1 2 3; do
    wait_height "$index" "$post_two_two_height"
  done
  wait_app_hash_convergence 0 1 2 3
  conflict_scan_end_height="$(local_height 0)"

  record_conflict_counts \
    "$((partition_height + 1))" \
    "$conflict_scan_end_height" \
    "$conflict_a_id" \
    "$conflict_b_id" \
    "$ROOT/evidence/partition-2-2-conflicts-final.json" \
    >"$ROOT/evidence/partition-2-2-conflicts-final.log"
  test "$(
    jq -r '.total_conflicting_commands_committed' \
      "$ROOT/evidence/partition-2-2-conflicts-final.json"
  )" = "1"
  run_safety_evidence partition-2-2-healed 0 1 2 3
  final_height="$(
    jq -r '.common_tip_height | tonumber' \
      "$ROOT/evidence/partition-2-2-healed.json"
  )"
  final_hash="$(
    jq -r '.nodes[0].local_app_hash' \
      "$ROOT/evidence/partition-2-2-healed.json"
  )"
  printf 'TRNM_COMETBFT_PARTITION_CASE_OK case=2-2 active_proxy_cut=verified stalled=verified pre_heal_mempools=verified conflicting_nonce_committed=1 heal=verified post_heal_liveness=verified\n'
fi

printf 'TRNM_COMETBFT_PARTITION_MATRIX_OK case=%s height=%s app_hash=%s active_proxy_cut=verified expected_peer_sets_observed=verified block_id_unique=verified root=%s\n' \
  "$CASE" "$final_height" "$final_hash" "$ROOT"
