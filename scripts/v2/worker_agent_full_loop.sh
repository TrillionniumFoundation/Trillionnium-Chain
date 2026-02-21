#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="${STATE:-/tmp/trnm-worker-agent-state.json}"
SUBMIT_LOG="${SUBMIT_LOG:-/tmp/trnm-worker-agent-submits.jsonl}"
VERIFY_DIR="${VERIFY_DIR:-/tmp/trnm-worker-verify}"
ACK_LOG="${ACK_LOG:-/tmp/trnm-worker-agent-acks.jsonl}"

cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

# Gate default: prefer command-mode adapter path (closer to real tx flow).
: "${TRNM_TX_ADAPTER_MODE:=command}"
: "${TRNM_TX_CLI:=echo}"
export TRNM_TX_ADAPTER_MODE TRNM_TX_CLI

OUT_JSON="/tmp/trnm-worker-runonce.json"
cargo run -q -p trnm-worker-agent -- run-once --state "$STATE" --worker worker1 --payload "demo-payload" --submit --submit-log "$SUBMIT_LOG" > "$OUT_JSON"

cargo run -q -p trnm-worker-agent -- flush-submissions --submit-log "$SUBMIT_LOG" --execute --adapter-cmd "./scripts/worker_tx_adapter.sh" --ack-log "$ACK_LOG"

TASK_ID=$(python3 - <<'PY' "$OUT_JSON"
import json,sys
print(json.load(open(sys.argv[1]))['task_id'])
PY
)

cd "$ROOT"
ACK_LOG="$ACK_LOG" ./scripts/v2/worker_agent_verify_with_rpc.sh "$TASK_ID"

echo "[OK] worker-agent full loop completed task_id=$TASK_ID"
