#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/pr5-reconcile/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

EVENT_LOG="${EVENT_LOG:-$ROOT/trillionnium-rust/run/event-field-check.log}"
REPORT="$RUN_DIR/reconcile-report.txt"

if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR5][INFO] event log not found, generating via check_event_fields.sh"
  (
    cd "$ROOT/trillionnium-rust"
    MVP_MODE=prod ALLOW_MISSING_RESOLVE_EVENT=0 ./scripts/check_event_fields.sh
  ) >"$RUN_DIR/check_event_fields.log" 2>&1
fi

if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR5][FAIL] missing event log after generation: $EVENT_LOG" >&2
  exit 2
fi

WINDOW_ARGS=()
if [[ -n "${BLOCKS:-}" ]]; then
  WINDOW_ARGS=(--blocks "$BLOCKS")
else
  WINDOW_ARGS=(--hours "${HOURS:-24}")
fi

STRICT_ARGS=()
if [[ "${STRICT_WINDOW:-1}" == "1" ]]; then
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
