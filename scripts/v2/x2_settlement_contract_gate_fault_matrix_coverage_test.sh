#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/x2_settlement_contract_gate.sh"

required_tests=(
  "x2_failure_path_confirm_failed_triggers_compensation_revert"
  "x3_prep_confirm_failure_blank_reason_falls_back_to_stable_contract_message"
  "x3_prep_duplicate_confirm_after_finalize_is_rejected_without_state_change"
  "x3_prep_reorder_confirm_with_older_height_after_finalize_is_rejected_without_state_change"
  "x3_prep_reorder_failed_confirm_after_finalize_is_rejected_without_state_change"
  "x3_prep_duplicate_failed_confirm_after_revert_is_rejected_without_state_change"
  "x3_prep_duplicate_confirmed_after_revert_is_rejected_without_state_change"
  "x3_prep_reorder_confirmed_after_revert_is_rejected_without_state_change"
  "x3_prep_stale_pending_on_degraded_heartbeat_triggers_compensation_revert"
  "x3_prep_degraded_heartbeat_takes_precedence_over_timeout_confirm_failure"
  "x3_prep_degraded_blank_reason_takes_precedence_over_confirm_failure_reason"
  "x3_prep_degraded_replay_keeps_first_compensation_reason_stable"
  "x3_prep_degraded_blank_reason_replay_keeps_fallback_reason_stable"
  "x3_prep_confirm_failed_replay_keeps_first_compensation_reason_stable"
  "x3_prep_confirm_failed_blank_reason_replay_keeps_fallback_reason_stable"
  "x3_prep_manual_degraded_blank_message_uses_stable_failure_fallback"
  "x3_prep_degraded_heartbeat_blank_reason_falls_back_to_stable_contract_message"
  "x3_prep_confirm_failure_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability"
  "x3_prep_degraded_heartbeat_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability"
  "x3_prep_confirm_failure_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis"
  "x3_prep_degraded_heartbeat_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis"
  "x3_prep_stale_pending_degraded_retry_hint_still_fails_closed_to_compensation"
  "x3_prep_stale_pending_degraded_empty_reason_uses_stable_fallback"
  "x3_prep_stale_pending_degraded_reason_collapses_crlf_and_unicode_separators_for_replay_stability"
  "x3_prep_stale_pending_degraded_reason_strips_bidi_embeddings_for_replay_stability"
  "x3_prep_stale_pending_degraded_reason_strips_bidi_isolates_for_replay_stability"
)

for test_name in "${required_tests[@]}"; do
  if ! grep -Fq "$test_name" "$GATE"; then
    echo "[FAIL] x2 gate missing fault-matrix coverage test: $test_name" >&2
    exit 1
  fi
done

echo "[PASS] x2 settlement contract gate keeps timeout/blank-reason precedence + finalize/revert duplicate/reorder guards + stale-pending fallback + reason sanitization anchors"
