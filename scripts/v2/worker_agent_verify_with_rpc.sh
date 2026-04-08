#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TASK_ID="${1:-42}"
OUT_DIR="${OUT_DIR:-/tmp/trnm-worker-verify}"
ACK_LOG="${ACK_LOG:-/tmp/trnm-worker-agent-acks.jsonl}"
mkdir -p "$OUT_DIR"

ACK_META_JSON="$OUT_DIR/ack-meta-$TASK_ID.json"
python3 - <<'PY' "$ACK_LOG" "$TASK_ID" "$ACK_META_JSON"
import json,sys,os
ack_path,task_id,out=sys.argv[1],int(sys.argv[2]),sys.argv[3]
assert os.path.exists(ack_path), f'ack log missing: {ack_path}'
acks=[]
with open(ack_path) as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        try:
            row=json.loads(line)
        except Exception:
            continue
        if row.get('task_id')==task_id:
            acks.append(row)
assert acks, f'no ack found for task_id={task_id}'
latest=acks[-1]
status=latest.get('status')
assert status in {'accepted','rejected','failed'}, f'unexpected ack status={status}'
if status == 'accepted':
    assert latest.get('commit_tx_hash'), f'empty commit_tx_hash for task_id={task_id}'
    assert latest.get('reveal_tx_hash'), f'empty reveal_tx_hash for task_id={task_id}'
elif status == 'rejected':
    assert latest.get('reason') or latest.get('reason_code'), f'missing reject reason for task_id={task_id}'
json.dump({'status': status}, open(out,'w'))
PY

ACK_STATUS="$(python3 - <<'PY' "$ACK_META_JSON"
import json,sys
print(json.load(open(sys.argv[1]))['status'])
PY
)"

if [[ "$ACK_STATUS" == "rejected" ]]; then
  echo "[OK] worker-agent rpc verify rejected task_id=$TASK_ID (skip accepted-task rpc lookup)"
  echo "[OK] worker-agent rpc verify task_id=$TASK_ID out_dir=$OUT_DIR ack_log=$ACK_LOG"
  exit 0
fi

TASK_JSON="$OUT_DIR/task-$TASK_ID.json"
EVENTS_JSON="$OUT_DIR/events-$TASK_ID.json"

cargo run -q -p trnm-rpc -- query-task "$TASK_ID" > "$TASK_JSON"
cargo run -q -p trnm-rpc -- query-events "$TASK_ID" > "$EVENTS_JSON"

python3 - <<'PY' "$TASK_JSON" "$EVENTS_JSON"
import json,sys
pj,ej=sys.argv[1],sys.argv[2]
t=json.load(open(pj))
e=json.load(open(ej))
assert 'task_id' in t and 'status' in t and 'version' in t, 'task schema invalid'
assert isinstance(e,list) and len(e)>=1, 'events empty'
required={'event_type','task_id','from_status','to_status','actor','tx_id','block_height','state_root','ts_unix_ms'}
for i,row in enumerate(e):
    miss=required-set(row.keys())
    assert not miss, f'event[{i}] missing {sorted(miss)}'
print('[OK] rpc verification passed + tx_hash hard-check passed')
PY

echo "[OK] worker-agent rpc verify task_id=$TASK_ID out_dir=$OUT_DIR ack_log=$ACK_LOG"