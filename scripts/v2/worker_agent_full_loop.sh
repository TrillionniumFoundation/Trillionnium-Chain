#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
STATE="${STATE:-/tmp/trnm-worker-agent-state-${RUN_TAG}.json}"
SUBMIT_LOG="${SUBMIT_LOG:-/tmp/trnm-worker-agent-submits-${RUN_TAG}.jsonl}"
VERIFY_DIR="${VERIFY_DIR:-/tmp/trnm-worker-verify-${RUN_TAG}}"
ACK_LOG="${ACK_LOG:-/tmp/trnm-worker-agent-acks-${RUN_TAG}.jsonl}"
WORKER="${WORKER:-worker1}"
PAYLOAD="${PAYLOAD:-demo-payload}"

cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

# Gate default: prefer command-mode adapter path (closer to real tx flow).
: "${TRNM_TX_ADAPTER_MODE:=command}"
# The base receipt loop is a hermetic adapter-state test. Never infer a local
# binary from `tx --help`: the active PoCO CLI intentionally retired the legacy
# commit-result/reveal-result surface. A caller that is deliberately exercising
# an external compatible CLI still injects TRNM_TX_CLI explicitly.
: "${TRNM_TX_CLI:=/bin/echo}"

# normalize local relative script path to absolute to survive cwd switches
if [[ "$TRNM_TX_CLI" == ./* || "$TRNM_TX_CLI" == scripts/* ]]; then
  TRNM_TX_CLI="$ROOT/${TRNM_TX_CLI#./}"
fi

export TRNM_TX_ADAPTER_MODE TRNM_TX_CLI

OUT_JSON="${OUT_JSON:-/tmp/trnm-worker-runonce-${RUN_TAG}.json}"
cargo run -q -p trnm-worker-agent -- run-once --state "$STATE" --worker "$WORKER" --payload "$PAYLOAD" --submit --submit-log "$SUBMIT_LOG" > "$OUT_JSON"

cargo run -q -p trnm-worker-agent -- flush-submissions --submit-log "$SUBMIT_LOG" --execute --adapter-cmd "./scripts/worker_tx_adapter.sh" --ack-log "$ACK_LOG"

TASK_ID=$(python3 - <<'PY' "$OUT_JSON"
import json,sys
print(json.load(open(sys.argv[1]))['task_id'])
PY
)

python3 - <<'PY' "$ACK_LOG" "$TASK_ID"
import json,sys
ack_path,task_id=sys.argv[1],int(sys.argv[2])
rows=[]
with open(ack_path, encoding='utf-8') as handle:
    for line in handle:
        if line.strip():
            row=json.loads(line)
            if int(row.get('task_id', -1)) == task_id:
                rows.append(row)
assert rows, f'no ack found for task_id={task_id}'
assert rows[-1].get('status') == 'accepted', (
    f"hermetic full-loop expected accepted ack, got {rows[-1].get('status')}"
)
PY

cd "$ROOT"
OUT_DIR="$VERIFY_DIR" ACK_LOG="$ACK_LOG" ./scripts/v2/worker_agent_verify_with_rpc.sh "$TASK_ID"

echo "[OK] worker-agent full loop completed task_id=$TASK_ID"
