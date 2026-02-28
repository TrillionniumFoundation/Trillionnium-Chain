#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

echo "[I2] capability token lifecycle gate: issue/revoke/replay/verify"

cargo test -p trnm-types issue_capability_rejects_height_before_did_creation_without_side_effects
cargo test -p trnm-types renew_capability_extends_expiry_and_appends_audit
cargo test -p trnm-types revoke_capability_replay_with_older_height_is_rejected_without_side_effects
cargo test -p trnm-types revoke_did_replay_repairs_legacy_uncascaded_capability_without_rewriting_did_timestamp
cargo test -p trnm-types revoke_did_replay_with_older_height_is_rejected_without_side_effects
cargo test -p trnm-types verify_capability_accepts_active_controller_and_matching_scope

echo "[I2][PASS] capability token lifecycle gate"
