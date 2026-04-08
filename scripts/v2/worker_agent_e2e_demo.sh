#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

STATE="${STATE:-/tmp/trnm-worker-agent-state.json}"
OUT="${OUT:-/tmp/trnm-worker-agent-runonce.json}"
SUBMIT_LOG="${SUBMIT_LOG:-/tmp/trnm-worker-agent-submits.jsonl}"

cargo run -q -p trnm-worker-agent -- run-once --state "$STATE" --worker worker1 --payload "demo-payload" --submit --submit-log "$SUBMIT_LOG" > "$OUT"
cargo run -q -p trnm-worker-agent -- flush-submissions --submit-log "$SUBMIT_LOG" --adapter-cmd "./scripts/worker_tx_adapter.sh" >/tmp/trnm-worker-flush.log

grep -q '"task_id"' "$OUT"
grep -q '"commit_hash"' "$OUT"
grep -q '"template_commit"' "$OUT"
grep -q '"task_id"' "$SUBMIT_LOG"
grep -q '\[dry-run\] adapter=' /tmp/trnm-worker-flush.log

echo "[OK] worker-agent e2e demo: out=$OUT submit_log=$SUBMIT_LOG"
