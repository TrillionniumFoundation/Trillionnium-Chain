#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] rpc_query_hardcap_enforcement: clamp_limit unit tests"
cargo test -q -p trnm-rpc clamp_limit_ -- --nocapture

echo "[TEST] rpc_query_hardcap_enforcement: query-events HTTP limit parser fallback"
cargo test -q -p trnm-rpc parse_query_events_limit_from_path_zero_uses_default_limit -- --nocapture

echo "[OK] rpc_query_hardcap_enforcement passed"
