#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

STATE="${STATE:-/tmp/trnm-worker-agent-state.json}"
OUT="${OUT:-/tmp/trnm-worker-agent-runonce.json}"

cargo run -q -p trnm-worker-agent -- run-once --state "$STATE" --worker worker1 --payload "demo-payload" > "$OUT"

grep -q '"task_id"' "$OUT"
grep -q '"commit_hash"' "$OUT"
grep -q '"template_commit"' "$OUT"

echo "[OK] worker-agent e2e demo: $OUT"
