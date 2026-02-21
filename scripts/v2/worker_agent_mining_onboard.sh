#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

AGENTS="${AGENTS:-3}"
REAL_CLI="${TRNM_TX_CLI:-}"
SKIP_GATES="${SKIP_GATES:-0}"

usage() {
  cat <<EOF
Usage:
  AGENTS=3 ./scripts/v2/worker_agent_mining_onboard.sh
  TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli ./scripts/v2/worker_agent_mining_onboard.sh
  SKIP_GATES=1 AGENTS=5 ./scripts/v2/worker_agent_mining_onboard.sh

Env:
  AGENTS       Number of worker identities for multi-agent smoke (default: 3)
  TRNM_TX_CLI  Real tx CLI path/name (optional). If set, real-cli gates are used.
  SKIP_GATES   1 to skip gate stage and run multi-agent smoke only.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

RUN_TAG="$(date +%Y%m%d-%H%M%S)-$$"
OUT_DIR="$ROOT/data/worker-onboard/$RUN_TAG"
mkdir -p "$OUT_DIR"

SUBMIT_LOG="$OUT_DIR/submits.jsonl"
ACK_LOG="$OUT_DIR/acks.jsonl"
EVENT_LOG="$OUT_DIR/events.jsonl"
PROGRESS_LOG="$OUT_DIR/progress.jsonl"
SUMMARY_JSON="$OUT_DIR/summary.json"

if [[ "$SKIP_GATES" != "1" ]]; then
  if [[ -n "$REAL_CLI" ]]; then
    echo "[stage] run real-cli worker receipt gates"
    TRNM_TX_CLI="$REAL_CLI" ./scripts/v2/run_worker_receipt_gates_real_cli.sh
  else
    echo "[stage] run worker receipt gates"
    ./scripts/v2/run_worker_receipt_gates.sh
  fi
fi

cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[stage] multi-agent smoke: agents=$AGENTS"
STATE_FILE="/tmp/trnm-worker-agent-state-${RUN_TAG}.json"
for i in $(seq 1 "$AGENTS"); do
  cargo run -q -p trnm-worker-agent -- run-once \
    --state "$STATE_FILE" \
    --worker "worker${i}" \
    --payload "demo-payload-${i}" \
    --submit \
    --submit-log "$SUBMIT_LOG" >/dev/null
  echo "  - submitted worker${i}"
done

cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --execute \
  --adapter-cmd "./scripts/worker_tx_adapter.sh" \
  --ack-log "$ACK_LOG" \
  --event-log "$EVENT_LOG" \
  --progress-log "$PROGRESS_LOG" >/dev/null

python3 - <<'PY' "$AGENTS" "$ACK_LOG" "$SUMMARY_JSON"
import json, sys
agents = int(sys.argv[1])
ack_log = sys.argv[2]
out = sys.argv[3]
accepted = rejected = failed = 0
rows = []
with open(ack_log, 'r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        obj=json.loads(line)
        rows.append(obj)
        s=obj.get('status')
        if s=='accepted': accepted += 1
        elif s=='rejected': rejected += 1
        elif s=='failed': failed += 1
terminal = accepted + rejected
summary = {
    'agents': agents,
    'acks_total': len(rows),
    'accepted': accepted,
    'rejected': rejected,
    'failed': failed,
    'terminal': terminal,
    'ok': (failed == 0 and terminal >= agents)
}
with open(out, 'w', encoding='utf-8') as w:
    json.dump(summary, w, indent=2, ensure_ascii=False)
print(json.dumps(summary, ensure_ascii=False))
if failed != 0 or terminal < agents:
    raise SystemExit(23)
PY

cat <<EOF
[OK] worker-agent onboarding completed
- run_tag: $RUN_TAG
- out_dir: $OUT_DIR
- submit_log: $SUBMIT_LOG
- ack_log: $ACK_LOG
- summary: $SUMMARY_JSON
EOF
