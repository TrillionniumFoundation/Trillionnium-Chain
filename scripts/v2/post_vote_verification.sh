#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

PROPOSAL_ID="${PROPOSAL_ID:-9001}"
TASK_ID="${TASK_ID:-}"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/post-vote-verification-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p "$OUT_DIR"

if [[ -z "$TASK_ID" ]]; then
  latest_log=$(ls -1t "$ROOT"/trillionnium/run/worker-agent/tx-adapter-*.jsonl 2>/dev/null | head -n1 || true)
  if [[ -n "$latest_log" ]]; then
    TASK_ID=$(tail -n 1 "$latest_log" | sed -n 's/.*"task_id":\([0-9]*\).*/\1/p')
  fi
fi
TASK_ID="${TASK_ID:-42}"

{
  echo "proposal_id=$PROPOSAL_ID"
  echo "task_id=$TASK_ID"

  echo "=== query proposal ==="
  cargo run -q -p trnm-rpc -- query-proposal "$PROPOSAL_ID"

  echo "=== query task ==="
  cargo run -q -p trnm-rpc -- query-task "$TASK_ID"

  echo "=== query challenge/events ==="
  cargo run -q -p trnm-rpc -- query-events "$TASK_ID"

  echo "=== query worker evidence (adapter logs) ==="
  latest_log=$(ls -1t "$ROOT"/trillionnium/run/worker-agent/tx-adapter-*.jsonl 2>/dev/null | head -n1 || true)
  if [[ -n "$latest_log" ]]; then
    echo "adapter_log=$latest_log"
    grep -n "\"task_id\":$TASK_ID" "$latest_log" || true
  else
    echo "adapter_log=none"
  fi

  echo "status=PASS"
} | tee "$OUT"

echo "[OK] post-vote verification: $OUT"
