#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export TRNM_TX_ADAPTER_MODE="command"
export TRNM_TX_CLI="echo"

# 1) produce one accepted submission via full loop
./scripts/v2/worker_agent_full_loop.sh >/tmp/trnm-replay-loop.out 2>&1

TASK_ID=$(python3 - <<'PY'
import re
s=open('/tmp/trnm-replay-loop.out').read()
m=re.search(r'task_id=(\d+)\s*$', s.strip(), re.M)
print(m.group(1) if m else '')
PY
)

if [[ -z "$TASK_ID" ]]; then
  echo "failed to parse task_id from worker_agent_full_loop output" >&2
  cat /tmp/trnm-replay-loop.out >&2
  exit 1
fi

# 2) replay should be rejected with rc=9
set +e
cd trillionnium-rust
./scripts/worker_tx_adapter.sh commit "$TASK_ID" worker1 deadbeef >/tmp/trnm-replay-guard.out 2>&1
RC=$?
set -e

if [[ "$RC" -ne 9 ]]; then
  echo "expected rc=9 for replay rejection, got rc=$RC" >&2
  cat /tmp/trnm-replay-guard.out >&2
  exit 1
fi

grep -q "replay rejected" /tmp/trnm-replay-guard.out

echo "[OK] worker replay guard test passed task_id=$TASK_ID rc=$RC"
