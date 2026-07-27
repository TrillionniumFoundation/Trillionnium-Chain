#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

mkdir -p run
OUT="run/event-replay-smoke.log"

# Ensure smoke check starts from a clean consensus replay baseline.
rm -rf run/consensus-wal

cargo run -q -p trnm-node --bin trnm-sim -- \
  --config configs/node1.toml \
  --block-ms 1 \
  --max-blocks 8 \
  --txs-per-block 1 \
  --demo-tasks 1 \
  --demo-keys 1 \
  --parallel-workers 2 > "$OUT"

python3 - <<'PY' "$OUT"
import os, sys, re
path = sys.argv[1]
if os.getenv("ALLOW_PARTIAL_EVENT_REPLAY", "0") == "1":
    need = ["create","accept","commit","reveal"]
else:
    need = ["create","accept","commit","reveal","challenge","resolve"]
seen = []
for line in open(path, encoding='utf-8', errors='ignore'):
    if not line.startswith('[event] '):
        continue
    m = re.search(r'event_type=([a-z_]+)', line)
    if not m:
        continue
    if 'task_id=1001' not in line:
        continue
    seen.append(m.group(1))

# Collapse repeated noise if any.
compact = []
for s in seen:
    if not compact or compact[-1] != s:
        compact.append(s)

idx = 0
for s in compact:
    if idx < len(need) and s == need[idx]:
        idx += 1

if idx != len(need):
    print('event replay mismatch')
    print('seen=', seen)
    print('compact=', compact)
    sys.exit(2)

print('event replay ok')
print('compact=', compact)
PY

echo "[OK] event replay smoke passed: $OUT"
