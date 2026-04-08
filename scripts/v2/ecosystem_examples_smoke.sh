#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

cargo run -q -p trnm-rpc -- query-task 42 | grep -q '"task_id"'
cargo run -q -p trnm-rpc -- query-proposal 9001 | grep -q '"proposal_id"'
cargo run -q -p trnm-rpc -- query-events 42 | grep -q '"event_type"'

echo "[OK] ecosystem examples smoke passed"
