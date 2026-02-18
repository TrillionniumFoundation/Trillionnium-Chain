#!/usr/bin/env bash
set -euo pipefail

# Alpha stability runner (continuous create -> smoke lifecycle)
#
# Usage:
#   BIN=./chaind ./tools/alpha_stability_runner.sh
#
# Optional env:
#   FROM=alice
#   CHAIN_ID=chain
#   NODE=http://127.0.0.1:26657
#   DURATION_SECONDS=86400
#   INTERVAL_SECONDS=45
#   MAX_RUNS=0               # 0 means unlimited until duration reached

FROM="${FROM:-alice}"
CHAIN_ID="${CHAIN_ID:-chain}"
NODE="${NODE:-http://127.0.0.1:26657}"
BIN="${BIN:-./chaind}"
DURATION_SECONDS="${DURATION_SECONDS:-86400}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-45}"
MAX_RUNS="${MAX_RUNS:-0}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/../docs/alpha-runs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"
LOG_FILE="$RUN_DIR/run.log"
SUMMARY_FILE="$RUN_DIR/summary.jsonl"
REPORT_FILE="$RUN_DIR/report.txt"

log() {
  local msg
  msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$msg" | tee -a "$LOG_FILE"
}

wait_tx() {
  local txhash="$1"
  local waited=0
  while (( waited < 30 )); do
    if "$BIN" q tx "$txhash" --node "$NODE" -o json >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

latest_task_id() {
  "$BIN" q workload list-task --node "$NODE" -o json | jq -r '(.Task // .task // []) | map((.id // "0")|tonumber) | max'
}

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing dependency: $1" >&2; exit 1; }
}

require jq
command -v "$BIN" >/dev/null 2>&1 || { echo "[ERR] binary not found: $BIN" >&2; exit 1; }

log "run_dir=$RUN_DIR"
log "starting preflight"
BIN="$BIN" bash "$ROOT_DIR/tools/compute_lifecycle_preflight.sh" 0 "$FROM" "$NODE" | tee -a "$LOG_FILE"

start_ts="$(date +%s)"
runs=0
ok=0
fail=0

while true; do
  now="$(date +%s)"
  elapsed=$((now - start_ts))
  if (( elapsed >= DURATION_SECONDS )); then
    log "duration reached (${elapsed}s), stopping"
    break
  fi
  if (( MAX_RUNS > 0 && runs >= MAX_RUNS )); then
    log "max runs reached ($MAX_RUNS), stopping"
    break
  fi

  runs=$((runs + 1))
  payload="ipfs://alpha-run-${runs}-$(date +%s)"

  log "run#$runs create-compute-job payload=$payload"
  tx_json="$($BIN tx compute create-compute-job "$payload" "cpu:1" \
    --from "$FROM" --chain-id "$CHAIN_ID" --fees 200stake --node "$NODE" --yes -o json)"
  tx_hash="$(echo "$tx_json" | jq -r '.txhash // empty')"
  log "run#$runs create tx=$tx_hash"
  if ! wait_tx "$tx_hash"; then
    fail=$((fail + 1))
    log "run#$runs create tx not indexed in time"
    sleep "$INTERVAL_SECONDS"
    continue
  fi

  job_id="$(latest_task_id)"
  log "run#$runs resolved job_id=$job_id"
  smoke_out="$(BIN="$BIN" SUMMARY_JSON=1 bash "$ROOT_DIR/tools/compute_lifecycle_smoke.sh" "$job_id" "$FROM" "$CHAIN_ID" "$NODE" 2>&1 || true)"
  echo "$smoke_out" >> "$LOG_FILE"
  summary_line="$(echo "$smoke_out" | sed -n 's/^SUMMARY_JSON=//p' | tail -n1)"

  if [[ -z "$summary_line" ]]; then
    fail=$((fail + 1))
    log "run#$runs missing SUMMARY_JSON (counted as fail)"
  else
    echo "$summary_line" >> "$SUMMARY_FILE"
    status="$(echo "$summary_line" | jq -r '.status // "failed"')"
    if [[ "$status" == "ok" ]]; then
      ok=$((ok + 1))
      log "run#$runs status=ok"
    else
      fail=$((fail + 1))
      reason="$(echo "$summary_line" | jq -r '.reason // "unknown"')"
      log "run#$runs status=failed reason=$reason"
    fi
  fi

  sleep "$INTERVAL_SECONDS"
done

success_rate="0"
if (( runs > 0 )); then
  success_rate="$(awk -v a="$ok" -v b="$runs" 'BEGIN { printf "%.2f", (a*100.0)/b }')"
fi

{
  echo "runs=$runs"
  echo "ok=$ok"
  echo "fail=$fail"
  echo "success_rate_pct=$success_rate"
  echo "log_file=$LOG_FILE"
  echo "summary_file=$SUMMARY_FILE"
} | tee "$REPORT_FILE"

log "done: runs=$runs ok=$ok fail=$fail success_rate=${success_rate}%"
