#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

# X2 contract gate: require both finalize and compensation paths to stay green.
cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x2_happy_path_heartbeat_ok_then_confirm_finalize \
  -- --nocapture

cargo test -p trnm-bridge-poc --test x2_settlement_loop \
  x2_failure_path_confirm_failed_triggers_compensation_revert \
  -- --nocapture
