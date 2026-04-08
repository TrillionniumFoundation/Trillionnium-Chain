#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
now_utc_compact() {
  date -u +%Y%m%d-%H%M%S
}
RUN_DIR="${RUN_DIR:-$ROOT/run/pr5-reconcile/$(now_utc_compact)}"
mkdir -p "$RUN_DIR"

EVENT_LOG="${EVENT_LOG:-$ROOT/trillionnium/run/event-field-check.log}"
REPORT="$RUN_DIR/reconcile-report.txt"

require_non_negative_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "[PR5][FAIL] invalid $name='$value' (expect non-negative integer)" >&2
    exit 2
  fi
}

require_bool_01() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "[PR5][FAIL] invalid $name='$value' (expect 0 or 1)" >&2
    exit 2
  fi
}

if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR5][INFO] event log not found, generating via check_event_fields.sh"
  (
    cd "$ROOT/trillionnium"
    MVP_MODE=prod ALLOW_MISSING_RESOLVE_EVENT=0 ./scripts/check_event_fields.sh
  ) >"$RUN_DIR/check_event_fields.log" 2>&1
fi

if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR5][FAIL] missing event log after generation: $EVENT_LOG" >&2
  exit 2
fi

WINDOW_ARGS=()
if [[ -n "${BLOCKS:-}" ]]; then
  require_non_negative_integer "BLOCKS" "$BLOCKS"
  WINDOW_ARGS=(--blocks "$BLOCKS")
else
  HOURS_VAL="${HOURS:-24}"
  require_non_negative_integer "HOURS" "$HOURS_VAL"
  WINDOW_ARGS=(--hours "$HOURS_VAL")
fi

STRICT_WINDOW_VAL="${STRICT_WINDOW:-1}"
require_bool_01 "STRICT_WINDOW" "$STRICT_WINDOW_VAL"
STRICT_ARGS=()
if [[ "$STRICT_WINDOW_VAL" == "1" ]]; then
  STRICT_ARGS=(--strict-window)
fi

python3 "$ROOT/scripts/v2/challenge_fundflow_reconcile.py" \
  --event-log "$EVENT_LOG" \
  "${WINDOW_ARGS[@]}" \
  "${STRICT_ARGS[@]}" \
  --report "$REPORT"

TRIAD_RUN_DIR="$RUN_DIR/triad"
RUN_DIR="$TRIAD_RUN_DIR" EVENT_LOG="$EVENT_LOG" "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency_gate.sh"

echo "[PR5][PASS] challenge reconcile gate report=$REPORT triad_dir=$TRIAD_RUN_DIR"
