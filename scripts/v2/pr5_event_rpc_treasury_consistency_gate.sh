#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/pr5-reconcile/$(date +%Y%m%d-%H%M%S)-triad}"
mkdir -p "$RUN_DIR"

EVENT_LOG="${EVENT_LOG:-$ROOT/trillionnium/run/event-field-check.log}"
if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR5][triad][INFO] event log not found, generating via check_event_fields.sh"
  (
    cd "$ROOT/trillionnium"
    MVP_MODE=prod ALLOW_MISSING_RESOLVE_EVENT=0 ./scripts/check_event_fields.sh
  ) >"$RUN_DIR/check_event_fields.log" 2>&1
fi

if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR5][triad][FAIL] missing event log: $EVENT_LOG" >&2
  exit 2
fi

PR5_OUT="$RUN_DIR/pr5-report"
SOURCE_LOG="$EVENT_LOG" OUT_DIR="$PR5_OUT" "$ROOT/scripts/v2/pr5_treasury_reconcile_report.sh" >"$RUN_DIR/pr5_treasury_reconcile_report.log" 2>&1
PR5_SUMMARY="$PR5_OUT/summary.txt"

RPC_JSON="$RUN_DIR/rpc-challenge-treasury.json"
(
  cd "$ROOT/trillionnium"
  cargo run -q -p trnm-rpc -- query-challenge-treasury --limit "${PR5_RPC_LIMIT:-200}" --json >"$RPC_JSON"
)

python3 "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency.py" \
  --event-log "$EVENT_LOG" \
  --pr5-summary "$PR5_SUMMARY" \
  --rpc-treasury-json "$RPC_JSON" \
  --report "$RUN_DIR/triad-consistency.txt"

echo "[PR5][triad][PASS] report=$RUN_DIR/triad-consistency.txt"