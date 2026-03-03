#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

# X2 contract gate: require both finalize and compensation paths to stay green.
# X3-prep contract guard: keep fallback compensation reason stable/replayable,
# and pin one reorder-path regression so compensation replay matrix remains covered.
cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x2_happy_path_heartbeat_ok_then_confirm_finalize \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x2_failure_path_confirm_failed_triggers_compensation_revert \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_confirm_failure_blank_reason_falls_back_to_stable_contract_message \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_reorder_confirm_with_older_height_after_finalize_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_reorder_failed_confirm_after_finalize_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_duplicate_confirm_after_finalize_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_duplicate_failed_confirm_after_revert_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_duplicate_confirmed_after_revert_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_reorder_confirmed_after_revert_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_stale_pending_on_degraded_heartbeat_triggers_compensation_revert \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_takes_precedence_over_timeout_confirm_failure \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_blank_reason_takes_precedence_over_confirm_failure_reason \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_replay_stability \
  x3_prep_degraded_replay_keeps_first_compensation_reason_stable \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_replay_stability \
  x3_prep_degraded_blank_reason_replay_keeps_fallback_reason_stable \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_replay_stability \
  x3_prep_confirm_failed_replay_keeps_first_compensation_reason_stable \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_replay_stability \
  x3_prep_confirm_failed_blank_reason_replay_keeps_fallback_reason_stable \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_manual_degraded_blank_message_uses_stable_failure_fallback \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_blank_reason_falls_back_to_stable_contract_message \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_confirm_failure_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_confirm_failure_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis \
  -- --nocapture
