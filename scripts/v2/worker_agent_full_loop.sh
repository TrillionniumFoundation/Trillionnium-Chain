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
if [[ -z "${TRNM_TX_CLI:-}" ]]; then
  CANDIDATE=""
  if command -v trnm-cli >/dev/null 2>&1; then
    CANDIDATE="trnm-cli"
  elif [[ -x "$ROOT/trillionnium-rust/target/debug/trnm-cli" ]]; then
    CANDIDATE="$ROOT/trillionnium-rust/target/debug/trnm-cli"
  elif command -v trnm-node >/dev/null 2>&1; then
    CANDIDATE="trnm-node"
  elif [[ -x "$ROOT/trillionnium-rust/target/debug/trnm-node" ]]; then
    CANDIDATE="$ROOT/trillionnium-rust/target/debug/trnm-node"
  fi

  if [[ -n "$CANDIDATE" ]] && "$CANDIDATE" tx --help >/dev/null 2>&1; then
    TRNM_TX_CLI="$CANDIDATE"
  else
    TRNM_TX_CLI="echo"
  fi
fi

# normalize local relative script path to absolute to survive cwd switches
if [[ "$TRNM_TX_CLI" == ./* || "$TRNM_TX_CLI" == scripts/* ]]; then
  TRNM_TX_CLI="$ROOT/${TRNM_TX_CLI#./}"
fi

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
