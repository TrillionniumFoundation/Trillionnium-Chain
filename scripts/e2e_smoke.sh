#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/qianqi/.openclaw/workspace/TrillionniumChain"
BIN="$ROOT/build/chaind"
WORKER_DIR="$ROOT/worker"
WORKER_LOG="$WORKER_DIR/worker.log"
TASK_PATH="$ROOT/tasks/example_futures"
COUNT="${1:-2}"

echo "[1/5] Ensure chain is running..."
$BIN status >/dev/null

echo "[2/5] Ensure single worker instance..."
pkill -f "$WORKER_DIR/main.py start" || true
rm -f "$WORKER_DIR/.worker.lock"
: > "$WORKER_LOG"
(
  cd "$WORKER_DIR"
  nohup python3 main.py start > worker.log 2>&1 &
)
sleep 3

echo "[3/5] Submit $COUNT jobs..."
"$ROOT/scripts/submit_jobs.sh" "$TASK_PATH" cpu "$COUNT" >/tmp/trnm_smoke_submit.log 2>&1 || {
  cat /tmp/trnm_smoke_submit.log
  exit 1
}

echo "[4/5] Wait for worker processing..."
# conservative wait: ~35s per job max
sleep $((COUNT * 35))

echo "[5/5] Verify commits in worker log..."
COMMITS=$(grep -c "result committed on-chain" "$WORKER_LOG" || true)
echo "Committed count in log: $COMMITS"
if [[ "$COMMITS" -lt "$COUNT" ]]; then
  echo "SMOKE FAILED: expected >=$COUNT commits"
  tail -n 200 "$WORKER_LOG"
  exit 2
fi

echo "SMOKE PASS ✅"
tail -n 80 "$WORKER_LOG"
