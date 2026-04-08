#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export TRNM_TX_ADAPTER_MODE="command"
export TRNM_TX_CLI="echo"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
LOOP_OUT="${LOOP_OUT:-/tmp/trnm-replay-loop-${RUN_TAG}.out}"
REPLAY_OUT="${REPLAY_OUT:-/tmp/trnm-replay-guard-${RUN_TAG}.out}"
export TRNM_TX_ADAPTER_OUT_LOG="/tmp/trnm-worker-adapter-replay-${RUN_TAG}.jsonl"

# 1) produce one accepted submission via full loop
REPLAY_STATE="/tmp/trnm-worker-replay-state-${RUN_TAG}.json"
REPLAY_SUBMIT_LOG="/tmp/trnm-worker-replay-submits-${RUN_TAG}.jsonl"
REPLAY_ACK_LOG="/tmp/trnm-worker-replay-acks-${RUN_TAG}.jsonl"
REPLAY_VERIFY_DIR="/tmp/trnm-worker-replay-verify-${RUN_TAG}"
RUN_TAG="$RUN_TAG" \
STATE="$REPLAY_STATE" \
SUBMIT_LOG="$REPLAY_SUBMIT_LOG" \
ACK_LOG="$REPLAY_ACK_LOG" \
VERIFY_DIR="$REPLAY_VERIFY_DIR" \
./scripts/v2/worker_agent_full_loop.sh >"$LOOP_OUT" 2>&1

TASK_ID=$(python3 - <<'PY' "$LOOP_OUT" "$REPLAY_ACK_LOG"
import json,re,sys
loop_out, ack_log = sys.argv[1], sys.argv[2]

# primary: parse from full-loop stdout (allow anywhere in line)
s = open(loop_out).read()
matches = re.findall(r'task_id=(\d+)', s)
if matches:
    print(matches[-1])
    raise SystemExit(0)

# fallback: parse from ack log jsonl (more stable than text output)
try:
    with open(ack_log) as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            rec=json.loads(line)
            if isinstance(rec, dict) and rec.get('task_id') is not None:
                print(rec['task_id'])
                raise SystemExit(0)
except FileNotFoundError:
    pass

print('')
PY
)

if [[ -z "$TASK_ID" ]]; then
  echo "failed to parse task_id from worker_agent_full_loop output/ack log" >&2
  cat "$LOOP_OUT" >&2
  exit 1
fi

# 2) replay should be rejected with rc=9
set +e
cd trillionnium
./scripts/worker_tx_adapter.sh commit "$TASK_ID" worker1 deadbeef >"$REPLAY_OUT" 2>&1
RC=$?
set -e

if [[ "$RC" -ne 9 ]]; then
  echo "expected rc=9 for replay rejection, got rc=$RC" >&2
  cat "$REPLAY_OUT" >&2
  exit 1
fi

grep -q "replay rejected" "$REPLAY_OUT"

echo "[OK] worker replay guard test passed task_id=$TASK_ID rc=$RC"
