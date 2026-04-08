#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium"

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
  x3_prep_confirm_failure_reason_strips_u2065_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_confirm_failure_reason_strips_mvs_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_reason_sanitizes_bom_and_word_joiner_controls_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_reason_strips_directional_marks_and_cgj_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_reason_strips_variation_selectors_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_confirm_failure_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_confirm_failure_reason_strips_plane14_tags_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_reason_unicode_over_cap_truncates_once_with_terminal_ellipsis \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_retry_hint_still_fails_closed_to_compensation \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_empty_reason_uses_stable_fallback \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_directional_marks_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_cgj_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_invisible_math_operators_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_collapses_crlf_and_unicode_separators_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_bidi_embeddings_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_soft_hyphen_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_bidi_isolates_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_bom_and_word_joiner_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_legacy_bidi_isolates_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_strips_plane14_tags_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_matrix \
  x3_prep_stale_pending_degraded_reason_collapses_figure_and_narrow_nbsp_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x3_compensation_unicode_controls \
  x3_prep_stale_pending_degraded_reason_strips_u2065_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc \
  normalize_compensation_reason_collapses_ogham_space_mark_for_replay_stability \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_degraded_heartbeat_with_non_canonical_operator_subject_fails_closed_without_state_change \
  -- --nocapture

echo "[X2][PASS] settlement contract gate"
