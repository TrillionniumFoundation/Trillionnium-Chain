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
  x3_prep_reorder_failed_confirm_after_finalize_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_duplicate_failed_confirm_after_revert_is_rejected_without_state_change \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_stale_pending_on_degraded_heartbeat_triggers_compensation_revert \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x3_prep_manual_degraded_blank_message_uses_stable_failure_fallback \
  -- --nocapture
