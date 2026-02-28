#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

echo "[I2] capability token lifecycle gate: issue/revoke/replay/verify"

cargo test -p trnm-types issue_capability_rejects_height_before_did_creation_without_side_effects
cargo test -p trnm-types renew_capability_extends_expiry_and_appends_audit
cargo test -p trnm-types renew_capability_with_same_expiry_is_idempotent_without_new_audit
cargo test -p trnm-types renew_capability_rejects_previously_revoked_token_without_side_effects
cargo test -p trnm-types revoke_capability_replay_with_older_height_is_rejected_without_side_effects
cargo test -p trnm-types revoke_did_replay_repairs_legacy_uncascaded_capability_without_rewriting_did_timestamp
cargo test -p trnm-types verify_capability_accepts_active_controller_and_matching_scope
cargo test -p trnm-types verify_capability_rejects_scope_mismatch_without_side_effects
cargo test -p trnm-types verify_capability_rejects_unknown_token_without_side_effects
cargo test -p trnm-types verify_capability_rejects_expired_token_without_side_effects
cargo test -p trnm-types verify_capability_rejects_revoked_did_even_if_token_looks_active
cargo test -p trnm-types verify_capability_allows_historical_height_before_did_revocation
cargo test -p trnm-types verify_capability_rejects_inactive_or_unauthorized_actor

echo "[I2][PASS] capability token lifecycle gate"
