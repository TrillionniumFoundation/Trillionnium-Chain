#!/usr/bin/env bash
set -euo pipefail

# Template helper for Testnet governance-based D-positive resolve.
# This script does NOT submit a governance proposal automatically.
# It prepares parameters + verification commands to reduce operator mistakes.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
KEYRING="${KEYRING:-test}"
TASK_ID="${TASK_ID:-}"
FINAL_RESULT_HASH="${FINAL_RESULT_HASH:-badresult123}"
CHALLENGE_SUCCEEDED="${CHALLENGE_SUCCEEDED:-true}"
MEMO="${MEMO:-gov resolve challenge}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

if [[ -z "$TASK_ID" ]]; then
  TASK_ID="$($BIN query workload list-task -o json --node "$NODE" --home "$HOME_DIR" | python3 -c 'import json,sys;o=json.load(sys.stdin);ids=[int(t.get("id",0)) for t in o.get("Task",[]) if str(t.get("status","0"))=="4" and str(t.get("id","0")).isdigit()];print(max(ids) if ids else 0)')"
fi

if [[ "$TASK_ID" -le 0 ]]; then
  echo "No challenged task found. Run scenario_C_challenge.sh first."
  exit 1
fi

worker_addr="$($BIN keys show alice -a --keyring-backend "$KEYRING" --home "$HOME_DIR")"
set +e
stake_json="$($BIN query workload show-worker "$worker_addr" -o json --node "$NODE" --home "$HOME_DIR" 2>/dev/null)"
stake_rc=$?
set -e
if [[ $stake_rc -eq 0 && -n "$stake_json" ]]; then
  stake_before="$(echo "$stake_json" | python3 -c 'import json,sys;o=json.load(sys.stdin);w=o.get("worker") or o.get("Worker") or {}; print(int(w.get("stake",0)))')"
else
  stake_before="N/A (worker not in active set)"
fi

log "Prepared governance resolve template"
echo "TASK_ID=$TASK_ID"
echo "CHALLENGE_SUCCEEDED=$CHALLENGE_SUCCEEDED"
echo "FINAL_RESULT_HASH=$FINAL_RESULT_HASH"
echo "MEMO=$MEMO"
echo "WORKER_ADDR=$worker_addr"
echo "STAKE_BEFORE=$stake_before"

cat <<EOF

=== Governance Proposal Payload (concept) ===
Message type: /chain.workload.MsgResolveChallenge
Fields:
- creator: <gov-authority-module-address>
- task_id: $TASK_ID
- challenge_succeeded: $CHALLENGE_SUCCEEDED
- final_result_hash: $FINAL_RESULT_HASH
- memo: $MEMO

=== Submit Route ===
Use your established x/gov proposal command flow in testnet.
(Deliberately not auto-submitted by this template.)

=== Post-Execution Verification ===
$BIN query workload show-task $TASK_ID -o json --node $NODE --home $HOME_DIR
$BIN query workload show-worker $worker_addr -o json --node $NODE --home $HOME_DIR

Expected:
- task status transitions from CHALLENGED(4) to terminal status (typically SLASHED(6) when challenge_succeeded=true)
- worker stake decreases according to worker_slash_percent_on_bad_result
EOF
