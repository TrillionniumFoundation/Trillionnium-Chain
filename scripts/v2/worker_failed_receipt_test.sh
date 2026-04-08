#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}"
STATE="${STATE:-/tmp/trnm-worker-fail-state-${RUN_TAG}.json}"
SUBMIT_LOG="${SUBMIT_LOG:-/tmp/trnm-worker-fail-submits-${RUN_TAG}.jsonl}"
ACK_LOG="${ACK_LOG:-/tmp/trnm-worker-fail-acks-${RUN_TAG}.jsonl}"
OUT_JSON="${OUT_JSON:-/tmp/trnm-worker-fail-runonce-${RUN_TAG}.json}"
ADAPTER_FAIL="${ADAPTER_FAIL:-/tmp/trnm-worker-fail-adapter-${RUN_TAG}.sh}"

rm -f "$STATE" "$SUBMIT_LOG" "$ACK_LOG" "$OUT_JSON" "$ADAPTER_FAIL"

cat > "$ADAPTER_FAIL" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[adapter] simulated failure tx_hash=deadbeef"
exit 42
EOF
chmod +x "$ADAPTER_FAIL"

cargo run -q -p trnm-worker-agent -- run-once \
  --state "$STATE" \
  --worker worker1 \
  --payload "demo-payload-fail" \
  --submit \
  --submit-log "$SUBMIT_LOG" > "$OUT_JSON"

cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --execute \
  --adapter-cmd "$ADAPTER_FAIL" \
  --max-retries 0 \
  --ack-log "$ACK_LOG" > /tmp/trnm-worker-fail-flush.out

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
        if not line:
            continue
        rows.append(json.loads(line))
rows=[r for r in rows if r.get('task_id')==tid]
assert rows, f'no ack for task_id={tid}'
last=rows[-1]
status=last.get('status')
assert status in {'failed','rejected'}, f"expected failed/rejected, got {status}"
assert last.get('commit_tx_hash'), 'missing commit_tx_hash on terminal negative ack'
if status == 'rejected':
    assert last.get('reason') or last.get('reason_code'), 'missing rejection reason'
print('[OK] worker failed receipt test passed task_id=%s status=%s' % (tid,status))
PY
