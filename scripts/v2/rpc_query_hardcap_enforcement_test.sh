#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] rpc_query_hardcap_enforcement: clamp_limit unit tests"
cargo test -q -p trnm-rpc clamp_limit_ -- --nocapture

echo "[TEST] rpc_query_hardcap_enforcement: query-events HTTP limit parser fallback"
cargo test -q -p trnm-rpc parse_query_events_limit_from_path_zero_uses_default_limit -- --nocapture

echo "[TEST] rpc_query_hardcap_enforcement: wrapped numeric query limits stay accepted"
cargo test -q -p trnm-rpc parse_query_events_limit_from_path_accepts_wrapped_numeric_limit -- --nocapture

echo "[TEST] rpc_query_hardcap_enforcement: duplicate limit query keys fail closed"
cargo test -q -p trnm-rpc parse_query_events_limit_from_path_rejects_duplicate_limit_keys -- --nocapture

echo "[TEST] rpc_query_hardcap_enforcement: malformed limit keys fail closed"
cargo test -q -p trnm-rpc parse_query_events_limit_from_path_rejects_malformed_limit_keys -- --nocapture

echo "[OK] rpc_query_hardcap_enforcement passed"
