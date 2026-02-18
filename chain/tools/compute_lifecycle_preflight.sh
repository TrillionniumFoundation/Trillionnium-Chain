#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./tools/compute_lifecycle_preflight.sh [JOB_ID] [FROM] [NODE]

JOB_ID="${1:-}"
FROM="${2:-alice}"
NODE="${3:-http://127.0.0.1:26657}"
BIN="${BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x "./chaind" ]]; then BIN="./chaind"; else BIN="chaind"; fi
fi
MIN_STAKE="${MIN_STAKE:-100000}"

log(){ printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
fail(){ log "[ERR] $*"; exit 1; }

command -v "$BIN" >/dev/null 2>&1 || fail "binary not found: $BIN"
command -v jq >/dev/null 2>&1 || fail "jq not found"

status="$($BIN status --node "$NODE" -o json 2>/dev/null || true)"
[[ -n "$status" ]] || fail "node unreachable: $NODE"
height="$(echo "$status" | jq -r '.sync_info.latest_block_height // .SyncInfo.latest_block_height // empty')"
[[ -n "$height" ]] || fail "cannot read node height"
log "node ok: height=$height"

ADDR="$($BIN keys show "$FROM" -a)"
DENOM="$($BIN q workload params --node "$NODE" -o json | jq -r '.params.workloadDenom // .params.workload_denom // "utrnm"')"
BAL="$($BIN q bank balances "$ADDR" --node "$NODE" -o json | jq -r --arg d "$DENOM" '.balances[]? | select(.denom==$d) | .amount' | head -n1)"
BAL="${BAL:-0}"
log "balance: ${BAL}${DENOM}, required>=${MIN_STAKE}${DENOM}"
(( BAL >= MIN_STAKE )) || fail "insufficient stake denom balance for worker registration"

if ! $BIN q workload show-worker "$ADDR" --node "$NODE" -o json >/dev/null 2>&1; then
  fail "worker not registered: $ADDR"
fi
log "worker registered: $ADDR"

if [[ -n "$JOB_ID" ]]; then
  TASK="$($BIN q workload show-task "$JOB_ID" --node "$NODE" -o json 2>/dev/null || true)"
  [[ -n "$TASK" ]] || fail "job/task id not found on workload side: $JOB_ID"
  TSTATUS="$(echo "$TASK" | jq -r '.Task.status // .task.status // empty')"
  log "task/job exists: id=$JOB_ID status=$TSTATUS"
fi

log "OK: preflight checks passed"
