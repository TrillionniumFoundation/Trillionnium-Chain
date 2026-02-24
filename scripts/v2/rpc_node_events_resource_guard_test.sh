#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] rpc_node_events_resource_guard: custom-window cap + log-tail parsing"
cargo test -q -p trnm-rpc resolve_ops_window_custom_validation -- --nocapture
cargo test -q -p trnm-rpc read_log_tail_returns_recent_lines -- --nocapture

echo "[OK] rpc_node_events_resource_guard passed"
