#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUST_ROOT="$ROOT/trillionnium"
now_utc_compact() {
  date -u +%Y%m%d-%H%M%S
}
RUN_DIR="${RUN_DIR:-$ROOT/run/pr4-gates/$(now_utc_compact)}"
mkdir -p "$RUN_DIR"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[PR4][GATE] challenge fund-flow + audit visibility started"
echo "[PR4][GATE] artifacts=$RUN_DIR"

step() {
  local name="$1"
  shift
  local log="$RUN_DIR/${name}.log"
  echo "[PR4][RUN] $name"
  (
    cd "$RUST_ROOT"
    "$@"
  ) 2>&1 | tee "$log"
  echo "[PR4][PASS] $name"
}

# 1) 罚没/返还资金流向（challenge bond）
step bond_forfeiture_flow_test cargo test -q -p trnm-pouw challenge_uses_governance_window_and_resolve_marks_bond_outcome -- --nocapture
step bond_refund_flow_test cargo test -q -p trnm-pouw resolve_refunds_challenge_bond_when_worker_slashed -- --nocapture

# 2) 审计字段可见性（事件字段）
step event_audit_fields_visibility ./scripts/check_event_fields.sh

EVENT_LOG="$RUST_ROOT/run/event-field-check.log"
if [[ ! -f "$EVENT_LOG" ]]; then
  echo "[PR4][FAIL] missing event log: $EVENT_LOG"
  exit 2
fi

RESOLVE_LINE="$(grep '^\[event\] .*event_type=resolve ' "$EVENT_LOG" | head -n 1 || true)"
if [[ -z "$RESOLVE_LINE" ]]; then
  echo "[PR4][FAIL] no resolve event found in $EVENT_LOG"
  exit 3
fi

for token in "signer=" "challenger=" "tx_hash=" "slash_worker=" "resolution_code="; do
  if [[ "$RESOLVE_LINE" != *"$token"* ]]; then
    echo "[PR4][FAIL] resolve event missing token '$token'"
    echo "[PR4][FAIL] line=$RESOLVE_LINE"
    exit 4
  fi
done

SUMMARY="$RUN_DIR/summary.txt"
{
  echo "status=PASS"
  echo "gate=pr4_challenge_fundflow_audit"
  echo "bond_forfeiture_test=challenge_uses_governance_window_and_resolve_marks_bond_outcome"
  echo "bond_refund_test=resolve_refunds_challenge_bond_when_worker_slashed"
  echo "event_log=$EVENT_LOG"
  echo "resolve_event=$RESOLVE_LINE"
  echo "generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$SUMMARY"

echo "[PR4][PASS] all checks passed"
echo "[PR4][PASS] summary=$SUMMARY"