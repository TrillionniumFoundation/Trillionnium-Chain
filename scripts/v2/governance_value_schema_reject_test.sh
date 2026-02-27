#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] governance_value_schema_reject: invalid value should be rejected"
cargo test -q -p trnm-state governance_param_schema_rejects_invalid_u64_values -- --nocapture
cargo test -q -p trnm-state emergency_pause_requires_strict_bool_literal -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_is_immediate_and_non_cancellable -- --nocapture
cargo test -q -p trnm-state emergency_pause_checked_path_rejects_non_canonical_key_id -- --nocapture

echo "[OK] governance_value_schema_reject passed"
