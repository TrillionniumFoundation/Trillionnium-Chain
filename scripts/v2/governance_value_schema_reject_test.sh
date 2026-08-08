#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

cd "$ROOT/trillionnium"

echo "[TEST] governance_value_schema_reject: invalid value should be rejected"
cargo test -q -p trnm-state governance_param_schema_rejects_invalid_u64_values -- --nocapture
cargo test -q -p trnm-state emergency_pause_requires_strict_bool_literal -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_is_immediate_and_non_cancellable -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_noop_update_is_idempotent_after_pause -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_rejects_non_canonical_key_id -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_key_id_validation_precedes_bool_schema_validation -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_rejects_key_id_shadowing -- --nocapture
cargo test -q -p trnm-state emergency_pause_does_not_bypass_sensitive_timelock_guards -- --nocapture
cargo test -q -p trnm-rpc governance_state_merge_gate_keeps_emergency_pause_seeded_unpaused -- --nocapture
cargo test -q -p trnm-rpc governance_state_merge_gate_rejects_non_canonical_emergency_pause_key_id -- --nocapture
cargo test -q -p trnm-rpc governance_state_merge_gate_emergency_pause_rejects_whitespace_bool_without_side_effects -- --nocapture

echo "[OK] governance_value_schema_reject passed"
