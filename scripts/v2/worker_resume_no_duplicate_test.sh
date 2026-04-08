#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
STATE="${STATE:-/tmp/trnm-worker-resume-state-${RUN_TAG}.json}"
SUBMIT_LOG="${SUBMIT_LOG:-/tmp/trnm-worker-resume-submits-${RUN_TAG}.jsonl}"
ACK_LOG="${ACK_LOG:-/tmp/trnm-worker-resume-acks-${RUN_TAG}.jsonl}"
OUT_JSON="${OUT_JSON:-/tmp/trnm-worker-resume-runonce-${RUN_TAG}.json}"
ADAPTER_PARTIAL="${ADAPTER_PARTIAL:-/tmp/trnm-worker-partial-adapter-${RUN_TAG}.sh}"
PASS1_OUT="${PASS1_OUT:-/tmp/trnm-worker-resume-pass1-${RUN_TAG}.out}"
PASS2_OUT="${PASS2_OUT:-/tmp/trnm-worker-resume-pass2-${RUN_TAG}.out}"

rm -f "$STATE" "$SUBMIT_LOG" "$ACK_LOG" "$OUT_JSON" "$ADAPTER_PARTIAL" "$PASS1_OUT" "$PASS2_OUT"

# avoid collision with historical adapter logs (replay check is task_id-based)
# Use Python for microsecond epoch generation because `date +%s%N` is not portable
# across GNU/BSD runners (BSD `date` may emit a literal `N`).
START_ID="$(python3 - <<'PY'
import time
print(time.time_ns() // 1000)
PY
)"
printf '{"last_task_id": %s}\n' "$START_ID" > "$STATE"

cat > "$ADAPTER_PARTIAL" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
kind="${1:-}"
if [[ "$kind" == "commit" ]]; then
  ./scripts/worker_tx_adapter.sh "$@"
  exit 0
fi
# simulate crash/failure before reveal reaches chain
echo "[adapter] simulated reveal transport failure"
exit 42
EOF
chmod +x "$ADAPTER_PARTIAL"

cargo run -q -p trnm-worker-agent -- run-once \
  --state "$STATE" \
  --worker worker1 \
  --payload "demo-payload-resume" \
  --submit \
  --submit-log "$SUBMIT_LOG" > "$OUT_JSON"

# pass1: commit succeeds, reveal fails -> failed ack expected
cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --execute \
  --adapter-cmd "$ADAPTER_PARTIAL" \
  --max-retries 0 \
  --ack-log "$ACK_LOG" > "$PASS1_OUT"

# pass2: restart with normal adapter; commit replay(rc=9) + reveal accepted should converge to accepted
cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --execute \
  --adapter-cmd "./scripts/worker_tx_adapter.sh" \
  --max-retries 0 \
  --ack-log "$ACK_LOG" > "$PASS2_OUT"

TASK_ID=$(python3 - <<'PY' "$OUT_JSON"
import json,sys
print(json.load(open(sys.argv[1]))['task_id'])
PY
)

python3 - <<'PY' "$ACK_LOG" "$TASK_ID"
import json,sys
ack,tid=sys.argv[1],int(sys.argv[2])
rows=[]
with open(ack) as f:
    for line in f:
        line=line.strip()
        if line:
            rows.append(json.loads(line))
rows=[r for r in rows if r.get('task_id')==tid]
assert rows, f'no ack for task_id={tid}'
statuses=[r.get('status') for r in rows]
assert ('failed' in statuses) or ('rejected' in statuses), f'expected an intermediate failed/rejected ack, got {statuses}'
assert 'accepted' in statuses, f'expected final accepted ack after resume, got {statuses}'
print('[OK] worker resume no-duplicate test passed task_id=%s statuses=%s' % (tid,statuses))
PY
