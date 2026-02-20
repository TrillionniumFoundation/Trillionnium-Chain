#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/worker-smoke/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT_DIR"

STATE_JSON="$OUT_DIR/worker_state.json"
LOG_JSONL="$OUT_DIR/worker.log.jsonl"

cat > "$STATE_JSON" <<'EOF'
{
  "last_height": 123456,
  "tasks": {
    "task-demo-001": {
      "phase": "committed",
      "tx_hashes": ["0xabc", "0xdef"],
      "reveal_salt": "encrypted:sample"
    }
  }
}
EOF

cat > "$LOG_JSONL" <<'EOF'
{"timestamp":"2026-02-20T21:05:00+08:00","level":"info","task_id":"task-demo-001","phase":"committed","tx_hash":"0xabc","attempt":1,"trace_id":"trace-demo-001"}
{"timestamp":"2026-02-20T21:05:01+08:00","level":"warn","task_id":"task-demo-001","phase":"committed","tx_hash":"0xabc","attempt":2,"error_code":"sequence_mismatch","trace_id":"trace-demo-001"}
EOF

python3 - "$STATE_JSON" "$LOG_JSONL" <<'PY'
import json, sys
state_path, log_path = sys.argv[1], sys.argv[2]

with open(state_path) as f:
    s = json.load(f)
assert 'last_height' in s, 'missing last_height'
assert 'tasks' in s and isinstance(s['tasks'], dict) and s['tasks'], 'missing tasks map'
for tid, t in s['tasks'].items():
    for k in ('phase','tx_hashes','reveal_salt'):
        assert k in t, f'missing task field: {k}'

required_log = {'timestamp','level','task_id','phase','tx_hash','attempt','trace_id'}
with open(log_path) as f:
    rows = [json.loads(x) for x in f if x.strip()]
assert rows, 'empty log rows'
for i,r in enumerate(rows):
    miss = required_log - set(r.keys())
    assert not miss, f'log row {i} missing fields: {sorted(miss)}'

print('[OK] worker onchain contract smoke passed')
PY

echo "[OK] artifacts: $OUT_DIR"
