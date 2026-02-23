#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[TEST] rpc_query_hardcap_enforcement: clamp_limit unit tests"
cargo test -q -p trnm-rpc clamp_limit_ -- --nocapture

echo "[OK] rpc_query_hardcap_enforcement passed"
