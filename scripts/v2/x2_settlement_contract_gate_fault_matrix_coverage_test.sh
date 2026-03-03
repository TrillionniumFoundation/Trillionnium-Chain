#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/x2_settlement_contract_gate.sh"

required_tests=(
  "x2_failure_path_confirm_failed_triggers_compensation_revert"
  "x3_prep_duplicate_confirm_after_finalize_is_rejected_without_state_change"
  "x3_prep_reorder_failed_confirm_after_finalize_is_rejected_without_state_change"
  "x3_prep_stale_pending_on_degraded_heartbeat_triggers_compensation_revert"
  "x3_prep_degraded_heartbeat_takes_precedence_over_timeout_confirm_failure"
)

for test_name in "${required_tests[@]}"; do
  if ! grep -Fq "$test_name" "$GATE"; then
    echo "[FAIL] x2 gate missing fault-matrix coverage test: $test_name" >&2
    exit 1
  fi
done

echo "[PASS] x2 settlement contract gate keeps timeout precedence + duplicate/reorder/stale-pending matrix anchors"
