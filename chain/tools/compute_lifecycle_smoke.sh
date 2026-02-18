#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./tools/compute_lifecycle_smoke.sh [JOB_ID] [FROM] [CHAIN_ID] [NODE]
#
# Example:
#   SUMMARY_JSON=1 ./tools/compute_lifecycle_smoke.sh 2102224 alice chain http://127.0.0.1:26657

JOB_ID="${1:-}"
FROM="${2:-alice}"
CHAIN_ID="${3:-chain}"
NODE="${4:-http://127.0.0.1:26657}"

BIN="${BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x "./chaind" ]]; then
    BIN="./chaind"
  else
    BIN="chaind"
  fi
fi
FEES="${FEES:-200stake}"
TX_WAIT_SECONDS="${TX_WAIT_SECONDS:-30}"
SUMMARY_JSON="${SUMMARY_JSON:-0}"
RESULT_HASH="${RESULT_HASH:-sha256:smoke-$(date +%s)}"
FAIL_SNAPSHOT_LINES="${FAIL_SNAPSHOT_LINES:-20}"

[[ -n "$JOB_ID" ]] || { echo "[ERR] missing JOB_ID" >&2; exit 1; }

START_TS="$(date +%s)"
LAST_TX=""
TASK_ID=""
LAST_STEP="init"

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

node_height() {
  "$BIN" status --node "$NODE" 2>/dev/null | jq -r '.SyncInfo.latest_block_height // .sync_info.latest_block_height // "?"'
}

node_syncing() {
  "$BIN" status --node "$NODE" 2>/dev/null | jq -r '.SyncInfo.catching_up // .sync_info.catching_up // "?"'
}

emit_failure_snapshot() {
  local reason="$1"
  local h s tx="<none>" task="<none>"
  h="$(node_height || echo '?')"
  s="$(node_syncing || echo '?')"

  if [[ -n "$LAST_TX" ]]; then
    tx="$($BIN q tx "$LAST_TX" --node "$NODE" -o json 2>/dev/null | jq -c --argjson n "$FAIL_SNAPSHOT_LINES" '{txhash:(.txhash // ""), code:(.code // 0), raw_log:(.raw_log // ""), events:((.events // [])[:$n])}' 2>/dev/null || echo '<tx-query-failed>')"
  fi

  if [[ -n "$TASK_ID" ]]; then
    task="$($BIN q workload show-task "$TASK_ID" --node "$NODE" -o json 2>/dev/null | jq -c '.' 2>/dev/null || echo '<task-query-failed>')"
  fi

  log "failure_snapshot: reason=$reason"
  log "failure_snapshot: step=$LAST_STEP node_height=$h catching_up=$s last_tx=${LAST_TX:-<none>} task_id=${TASK_ID:-<none>}"
  log "failure_snapshot: tx=$tx"
  log "failure_snapshot: task=$task"
}

die() {
  local reason="$*"
  log "[ERR] $reason"
  emit_failure_snapshot "$reason" || true
  if [[ "$SUMMARY_JSON" == "1" ]]; then
    echo "SUMMARY_JSON=$(jq -cn \
      --arg status failed \
      --arg reason "$reason" \
      --arg job_id "$JOB_ID" \
      --arg last_tx "$LAST_TX" \
      --arg task_id "$TASK_ID" \
      --arg last_step "$LAST_STEP" \
      '{status:$status,reason:$reason,job_id:$job_id,last_tx:$last_tx,task_id:$task_id,last_step:$last_step}')"
  fi
  exit 1
}

check_dependencies() {
  command -v "$BIN" >/dev/null 2>&1 || die "binary not found: $BIN"
  command -v jq >/dev/null 2>&1 || die "jq not found"
}

check_node_reachable() {
  local status_json
  if ! status_json="$($BIN status --node "$NODE" 2>/dev/null)"; then
    die "node unreachable at $NODE (start chain first, e.g. ignite chain serve)"
  fi

  local h s
  h="$(echo "$status_json" | jq -r '.SyncInfo.latest_block_height // .sync_info.latest_block_height // empty')"
  s="$(echo "$status_json" | jq -r 'if .SyncInfo.catching_up != null then (.SyncInfo.catching_up|tostring) elif .sync_info.catching_up != null then (.sync_info.catching_up|tostring) else empty end')"

  [[ -n "$h" ]] || die "node status missing latest_block_height at $NODE"
  [[ -n "$s" ]] || die "node status missing catching_up at $NODE"

  log "node reachable: height=$h catching_up=$s"
}

broadcast_tx() {
  local label="$1"
  shift

  LAST_STEP="$label"
  log "$label"
  local raw txhash code rawlog
  raw="$("$@" -o json)"
  txhash="$(echo "$raw" | jq -r '.txhash // empty')"
  code="$(echo "$raw" | jq -r '.code // 0')"
  rawlog="$(echo "$raw" | jq -r '.raw_log // empty')"

  [[ -n "$txhash" ]] || die "$label returned empty txhash"
  LAST_TX="$txhash"

  if [[ "$code" != "0" ]]; then
    die "$label failed: txhash=$txhash code=$code raw_log=${rawlog:-<empty>}"
  fi

  log "  txhash=$txhash"
}

wait_tx() {
  local txhash="$1"
  local waited=0
  LAST_STEP="wait-tx"
  while (( waited < TX_WAIT_SECONDS )); do
    if "$BIN" q tx "$txhash" --node "$NODE" -o json >/dev/null 2>&1; then
      local txj code raw
      txj="$($BIN q tx "$txhash" --node "$NODE" -o json)"
      code="$(echo "$txj" | jq -r '.code // 0')"
      raw="$(echo "$txj" | jq -r '.raw_log // ""')"
      if [[ "$code" != "0" ]]; then
        die "tx execution failed: tx=$txhash code=$code raw_log=${raw:-<empty>}"
      fi
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  die "tx not indexed in time: $txhash"
}

event_attr() {
  local txhash="$1" etype="$2" key="$3"
  "$BIN" q tx "$txhash" --node "$NODE" -o json | jq -r --arg et "$etype" --arg k "$key" '
    .events[]? | select(.type == $et) | .attributes[]? | select(.key == $k) | .value
  ' | tail -n1
}

check_dependencies
check_node_reachable
log "node height=$(node_height) catching_up=$(node_syncing)"

broadcast_tx "[1/3] request-job-execution" \
  "$BIN" tx compute request-job-execution \
  --job-id "$JOB_ID" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes
wait_tx "$LAST_TX"

broadcast_tx "[2/3] complete-job" \
  "$BIN" tx compute complete-job \
  --job-id "$JOB_ID" \
  --result "$RESULT_HASH" \
  --from "$FROM" \
  --chain-id "$CHAIN_ID" \
  --fees "$FEES" \
  --node "$NODE" \
  --yes
wait_tx "$LAST_TX"

LAST_STEP="extract-events"
TASK_ID="$(event_attr "$LAST_TX" "compute_complete_job" "task_id")"
[[ -n "$TASK_ID" ]] || die "cannot resolve task_id from compute_complete_job event"

WORKER_ADDR="$($BIN keys show "$FROM" -a)"
WORKER_EVENT="$(event_attr "$LAST_TX" "compute_complete_job" "worker")"
[[ "$WORKER_EVENT" == "$WORKER_ADDR" ]] || die "worker mismatch in compute_complete_job event: got=$WORKER_EVENT want=$WORKER_ADDR"

LAST_STEP="[3/3] verify workload task state"
log "$LAST_STEP"
TASK_JSON="$($BIN q workload show-task "$TASK_ID" --node "$NODE" -o json)"
TASK_STATUS="$(echo "$TASK_JSON" | jq -r '.Task.status // .task.status // empty')"
TASK_WORKER="$(echo "$TASK_JSON" | jq -r '.Task.worker // .task.worker // empty')"
TASK_RESULT="$(echo "$TASK_JSON" | jq -r '.Task.resultHash // .Task.result_hash // .task.resultHash // .task.result_hash // empty')"

[[ "$TASK_STATUS" == "2" ]] || die "task not completed: task_id=$TASK_ID status=$TASK_STATUS"
[[ "$TASK_WORKER" == "$WORKER_ADDR" ]] || die "task worker mismatch: got=$TASK_WORKER want=$WORKER_ADDR"
[[ "$TASK_RESULT" == "$RESULT_HASH" ]] || die "task result mismatch: got=$TASK_RESULT want=$RESULT_HASH"

END_TS="$(date +%s)"
DURATION="$((END_TS - START_TS))"

log "OK: compute lifecycle closed for job_id=$JOB_ID task_id=$TASK_ID duration=${DURATION}s"

if [[ "$SUMMARY_JSON" == "1" ]]; then
  echo "SUMMARY_JSON=$(jq -cn \
    --arg status ok \
    --arg job_id "$JOB_ID" \
    --arg task_id "$TASK_ID" \
    --arg tx_complete "$LAST_TX" \
    --arg worker "$WORKER_ADDR" \
    --arg result "$RESULT_HASH" \
    --arg last_step "$LAST_STEP" \
    --argjson duration_s "$DURATION" \
    '{status:$status,job_id:$job_id,task_id:$task_id,tx_complete:$tx_complete,worker:$worker,result_hash:$result,last_step:$last_step,duration_s:$duration_s}')"
fi
