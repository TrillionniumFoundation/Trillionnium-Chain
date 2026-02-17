#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./tools/lifecycle_smoke.sh [CHAIN_ID] [FROM] [NODE]

CHAIN_ID="${1:-chain}"
FROM="${2:-alice}"
NODE="${3:-http://127.0.0.1:26657}"
BIN="${BIN:-chaind}"
FEES="${FEES:-200stake}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"
MAX_WAIT_BLOCKS="${MAX_WAIT_BLOCKS:-300}"
TX_WAIT_SECONDS="${TX_WAIT_SECONDS:-30}"
SUMMARY_JSON="${SUMMARY_JSON:-0}"
FAIL_SNAPSHOT_LINES="${FAIL_SNAPSHOT_LINES:-40}"

LAST_LABEL=""
LAST_TXHASH=""

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

emit_failure_snapshot() {
  local reason="$1"
  local snap_height="?"
  local snap_sync="?"
  local unbonding="<unavailable>"
  local tx_json="<unavailable>"

  snap_height="$(latest_height 2>/dev/null || echo '?')"
  snap_sync="$(node_syncing 2>/dev/null || echo '?')"

  if [[ -n "${WORKER_ADDR:-}" ]]; then
    unbonding="$("$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json 2>/dev/null | jq -c '.' 2>/dev/null || echo '<not-found-or-query-failed>')"
  fi

  if [[ -n "$LAST_TXHASH" ]]; then
    tx_json="$("$BIN" q tx "$LAST_TXHASH" --node "$NODE" -o json 2>/dev/null | jq -c --argjson n "$FAIL_SNAPSHOT_LINES" '{txhash:(.txhash // ""), code:(.code // 0), raw_log:(.raw_log // ""), events:((.events // [])[:$n])}' 2>/dev/null || echo '<tx-query-failed>')"
  fi

  log "failure_snapshot: reason=$reason"
  log "failure_snapshot: node height=$snap_height catching_up=$snap_sync"
  log "failure_snapshot: worker=${WORKER_ADDR:-<unknown>} release_height=${RELEASE_HEIGHT:-<unknown>} waited_blocks=${COOLDOWN_WAITED_BLOCKS:-0} stagnant_rounds=${COOLDOWN_STAGNANT_ROUNDS:-0}"
  log "failure_snapshot: last_step=${LAST_LABEL:-<unknown>} last_tx=${LAST_TXHASH:-<none>}"
  log "failure_snapshot: unbonding=$unbonding"
  log "failure_snapshot: tx=$tx_json"

  if [[ "$SUMMARY_JSON" == "1" ]]; then
    log "SUMMARY_JSON: $(jq -cn \
      --arg status "failed" \
      --arg reason "$reason" \
      --arg worker "${WORKER_ADDR:-}" \
      --arg last_step "${LAST_LABEL:-}" \
      --arg last_tx "${LAST_TXHASH:-}" \
      --argjson release_height "${RELEASE_HEIGHT:-0}" \
      --argjson waited_blocks "${COOLDOWN_WAITED_BLOCKS:-0}" \
      --argjson stagnant_rounds "${COOLDOWN_STAGNANT_ROUNDS:-0}" \
      --arg node_height "$snap_height" \
      --arg catching_up "$snap_sync" \
      '{status:$status,reason:$reason,worker:$worker,last_step:$last_step,last_tx:$last_tx,release_height:$release_height,cooldown_waited_blocks:$waited_blocks,cooldown_stagnant_rounds:$stagnant_rounds,node_height:$node_height,catching_up:$catching_up}')"
  fi
}

die() {
  local reason="$*"
  log "[ERR] $reason" >&2
  emit_failure_snapshot "$reason" >&2 || true
  exit 1
}

now_epoch() {
  date +%s
}

latest_height() {
  "$BIN" status --node "$NODE" 2>/dev/null | jq -r '.SyncInfo.latest_block_height | tonumber'
}

node_syncing() {
  "$BIN" status --node "$NODE" 2>/dev/null | jq -r '.SyncInfo.catching_up'
}

check_dependencies() {
  command -v "$BIN" >/dev/null 2>&1 || die "binary not found: $BIN"
  command -v jq >/dev/null 2>&1 || die "jq not found"
}

check_node_reachable() {
  local h
  if ! h="$(latest_height)"; then
    die "cannot query node status from $NODE"
  fi
  log "node reachable: height=$h catching_up=$(node_syncing)"
}

broadcast_txhash() {
  local label="$1"
  shift

  LAST_LABEL="$label"

  local raw txhash code rawlog
  raw="$($@ -o json)"
  txhash="$(echo "$raw" | jq -r '.txhash // empty')"
  code="$(echo "$raw" | jq -r '.code // 0')"
  rawlog="$(echo "$raw" | jq -r '.raw_log // empty')"
  LAST_TXHASH="$txhash"

  [[ -n "$txhash" ]] || die "$label broadcast returned empty txhash. response=$raw"
  if [[ "$code" != "0" ]]; then
    die "$label broadcast failed: txhash=$txhash code=$code raw_log=${rawlog:-<empty>}"
  fi

  echo "$txhash"
}

wait_tx() {
  local txhash="$1"
  local waited=0

  while (( waited < TX_WAIT_SECONDS )); do
    if "$BIN" q tx "$txhash" --node "$NODE" -o json >/dev/null 2>&1; then
      return 0
    fi

    local h
    h="$(latest_height || echo '?')"
    log "  waiting tx inclusion... tx=$txhash waited=${waited}s height=$h"

    sleep 1
    waited=$(( waited + 1 ))
  done

  local h sync
  h="$(latest_height || echo '?')"
  sync="$(node_syncing || echo '?')"
  die "tx not found in time: tx=$txhash waited=${waited}s height=$h catching_up=$sync"
}

expect_event_attr() {
  local txhash="$1"
  local event_type="$2"
  local key="$3"
  local expected="$4"

  local got
  got="$("$BIN" q tx "$txhash" --node "$NODE" -o json | jq -r --arg et "$event_type" --arg k "$key" '
    .events[] | select(.type == $et) | .attributes[] | select(.key == $k) | .value
  ' | tail -n1)"

  if [[ "$got" != "$expected" ]]; then
    die "event validation failed for tx=$txhash event=$event_type key=$key expected=$expected got=${got:-<empty>}"
  fi

  log "  event_ok: $event_type.$key=$expected"
}

COOLDOWN_WAITED_BLOCKS=0
COOLDOWN_STAGNANT_ROUNDS=0
COOLDOWN_FINAL_HEIGHT=0

wait_for_release_height() {
  local release_height="$1"
  local current
  local waited=0
  local stagnant=0

  current="$(latest_height)"
  while (( current < release_height )); do
    if (( waited >= MAX_WAIT_BLOCKS )); then
      COOLDOWN_WAITED_BLOCKS="$waited"
      COOLDOWN_STAGNANT_ROUNDS="$stagnant"
      COOLDOWN_FINAL_HEIGHT="$current"
      die "cooldown wait timeout: current=$current release=$release_height waited_blocks=$waited stagnant_rounds=$stagnant catching_up=$(node_syncing || echo '?')"
    fi

    local remaining=$(( release_height - current ))
    log "  waiting cooldown... current=$current target=$release_height remaining=$remaining"
    sleep "$SLEEP_SECONDS"

    local next
    next="$(latest_height)"
    if (( next > current )); then
      waited=$(( waited + (next - current) ))
      stagnant=0
    else
      stagnant=$(( stagnant + 1 ))
      if (( stagnant % 5 == 0 )); then
        log "  cooldown stall diagnose: height=$next catching_up=$(node_syncing || echo '?') stagnant_rounds=$stagnant"
      fi
    fi
    current="$next"
  done

  COOLDOWN_WAITED_BLOCKS="$waited"
  COOLDOWN_STAGNANT_ROUNDS="$stagnant"
  COOLDOWN_FINAL_HEIGHT="$current"
  log "  cooldown reached at height=$current (target=$release_height)"
}

check_dependencies
check_node_reachable
START_TS="$(now_epoch)"
START_HEIGHT="$(latest_height)"
WORKER_ADDR="$($BIN keys show "$FROM" -a)"

log "[1/6] register-worker"
TX_REGISTER="$(broadcast_txhash register-worker "$BIN" tx workload register-worker \
  --node-id smoke-node \
  --ipfs-addr /ip4/127.0.0.1/tcp/4001 \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes)"
wait_tx "$TX_REGISTER"
log "  tx_register=$TX_REGISTER"
expect_event_attr "$TX_REGISTER" "workload_register_worker" "worker" "$WORKER_ADDR"

log "[2/6] request-unbonding"
TX_REQ="$(broadcast_txhash request-unbonding "$BIN" tx workload request-unbonding \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes)"
wait_tx "$TX_REQ"
log "  tx_request_unbonding=$TX_REQ"
expect_event_attr "$TX_REQ" "workload_request_unbonding" "worker" "$WORKER_ADDR"

AMOUNT="$("$BIN" q tx "$TX_REQ" --node "$NODE" -o json | jq -r '
  .events[] | select(.type=="workload_request_unbonding") | .attributes[] | select(.key=="amount") | .value
' | tail -n1)"
RELEASE_HEIGHT="$("$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json | jq -r '.unbonding.releaseHeight | tonumber')"

log "[3/6] query unbonding"
"$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json

log "[4/6] wait cooldown until release height"
wait_for_release_height "$RELEASE_HEIGHT"

log "[5/6] finalize-unbonding"
TX_FINALIZE="$(broadcast_txhash finalize-unbonding "$BIN" tx workload finalize-unbonding \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes)"
wait_tx "$TX_FINALIZE"
log "  tx_finalize_unbonding=$TX_FINALIZE"
expect_event_attr "$TX_FINALIZE" "workload_finalize_unbonding" "worker" "$WORKER_ADDR"
expect_event_attr "$TX_FINALIZE" "workload_finalize_unbonding" "amount" "$AMOUNT"

log "[6/6] verify unbonding removed"
if "$BIN" q workload show-unbonding "$WORKER_ADDR" --node "$NODE" -o json >/dev/null 2>&1; then
  die "unbonding still exists after finalize"
fi

END_TS="$(now_epoch)"
END_HEIGHT="$(latest_height)"
DURATION_S=$(( END_TS - START_TS ))
HEIGHT_DELTA=$(( END_HEIGHT - START_HEIGHT ))

log "summary: duration_s=$DURATION_S start_height=$START_HEIGHT end_height=$END_HEIGHT height_delta=$HEIGHT_DELTA waited_blocks=$COOLDOWN_WAITED_BLOCKS stagnant_rounds=$COOLDOWN_STAGNANT_ROUNDS tx_register=$TX_REGISTER tx_request_unbonding=$TX_REQ tx_finalize_unbonding=$TX_FINALIZE"
if [[ "$SUMMARY_JSON" == "1" ]]; then
  log "SUMMARY_JSON: $(jq -cn \
    --arg worker "$WORKER_ADDR" \
    --arg tx_register "$TX_REGISTER" \
    --arg tx_request_unbonding "$TX_REQ" \
    --arg tx_finalize_unbonding "$TX_FINALIZE" \
    --argjson start_height "$START_HEIGHT" \
    --argjson end_height "$END_HEIGHT" \
    --argjson height_delta "$HEIGHT_DELTA" \
    --argjson duration_s "$DURATION_S" \
    --argjson release_height "$RELEASE_HEIGHT" \
    --argjson cooldown_waited_blocks "$COOLDOWN_WAITED_BLOCKS" \
    --argjson cooldown_stagnant_rounds "$COOLDOWN_STAGNANT_ROUNDS" \
    '{worker:$worker,tx_register:$tx_register,tx_request_unbonding:$tx_request_unbonding,tx_finalize_unbonding:$tx_finalize_unbonding,start_height:$start_height,end_height:$end_height,height_delta:$height_delta,duration_s:$duration_s,release_height:$release_height,cooldown_waited_blocks:$cooldown_waited_blocks,cooldown_stagnant_rounds:$cooldown_stagnant_rounds}')"
fi

log "OK: lifecycle smoke completed with cooldown wait + finalize + event checks."