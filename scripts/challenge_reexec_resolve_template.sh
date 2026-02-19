#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/qianqi/.openclaw/workspace/TrillionniumChain"
BIN="$ROOT/build/chaind"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <task-id> <match|mismatch> [reexec-result-hash] [report-uri]"
  echo "Example: $0 12 mismatch sha256:abc ipfs://report-12"
  exit 1
fi

TASK_ID="$1"
OUTCOME="$2"
REEXEC_HASH="${3:-}"
REPORT_URI="${4:-}"

TASK_JSON="$($BIN query workload show-task "$TASK_ID" --home "$HOME_DIR" --node "$NODE" -o json)"
TASK_HASH="$(echo "$TASK_JSON" | jq -r '.Task.resultHash // .task.resultHash // ""')"

if [[ -z "$REEXEC_HASH" ]]; then
  REEXEC_HASH="$TASK_HASH"
fi

if [[ "$OUTCOME" == "mismatch" ]]; then
  SUCCEEDED=true
else
  SUCCEEDED=false
fi

MEMO="reexec_v0.1"
if [[ -n "$REPORT_URI" ]]; then
  MEMO="$MEMO report=$REPORT_URI"
fi

echo "# Re-execution resolve template"
echo "task_id=$TASK_ID"
echo "task_hash=$TASK_HASH"
echo "reexec_hash=$REEXEC_HASH"
echo "challenge_succeeded=$SUCCEEDED"
echo ""
echo "Run (authority):"
echo "$BIN tx workload resolve-challenge $TASK_ID $SUCCEEDED $REEXEC_HASH \"$MEMO\" --from <authority> --chain-id trillionnium --keyring-backend test --home $HOME_DIR --node $NODE --yes --fees 500stake"
