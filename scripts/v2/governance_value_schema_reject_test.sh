#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] governance_value_schema_reject: invalid value should be rejected"
cargo test -q -p trnm-state governance_param_schema_rejects_invalid_u64_values -- --nocapture
cargo test -q -p trnm-state emergency_pause_requires_strict_bool_literal -- --nocapture

echo "[OK] governance_value_schema_reject passed"
