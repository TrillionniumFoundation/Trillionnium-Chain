#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

cd "$ROOT/trillionnium"

echo "[TEST] settlement governance query: default mode and pending/live rollout semantics"
cargo test -q -p trnm-rpc settlement_governance_query_defaults_to_pouw_primary_when_live_params_are_absent -- --nocapture
cargo test -q -p trnm-rpc settlement_governance_query_surfaces_staged_shadow_and_hybrid_updates -- --nocapture
cargo test -q -p trnm-rpc settlement_governance_query_derives_live_hybrid_mode_from_configured_params -- --nocapture
cargo test -q -p trnm-rpc settlement_governance_query_shadow_mode_masks_configured_hybrid_weights_in_effective_weights -- --nocapture

echo "[OK] settlement governance query gate passed"
