#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TASK_ID="${1:-42}"
OUT_DIR="${OUT_DIR:-/tmp/trnm-worker-verify}"
mkdir -p "$OUT_DIR"

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
print('[OK] rpc verification passed')
PY

echo "[OK] worker-agent rpc verify task_id=$TASK_ID out_dir=$OUT_DIR"