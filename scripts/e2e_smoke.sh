#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/qianqi/.openclaw/workspace/TrillionniumChain"
BIN="$ROOT/build/chaind"
WORKER_DIR="$ROOT/worker"
WORKER_LOG="$WORKER_DIR/worker.log"
TASK_PATH="$ROOT/tasks/example_futures"
COUNT="${1:-2}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
KEY_NAME="${KEY_NAME:-alice}"

echo "[1/6] Ensure chain is running..."
$BIN status >/dev/null

echo "[2/6] Ensure single worker instance..."
pkill -f "main.py start" || true
rm -f "$WORKER_DIR/.worker.lock"
: > "$WORKER_LOG"
(
  cd "$WORKER_DIR"
  nohup python3 main.py start > worker.log 2>&1 &
)
sleep 3

echo "[3/6] Ensure worker is registered in workload module..."
WORKER_ADDR=$($BIN keys show "$KEY_NAME" -a --keyring-backend test)
if ! $BIN query workload show-worker "$WORKER_ADDR" --node tcp://127.0.0.1:26657 --home /Users/qianqi/.chain >/dev/null 2>&1; then
  echo "Worker $WORKER_ADDR not registered, registering now..."
  $BIN tx workload register-worker "$KEY_NAME" "ipfs://worker-$KEY_NAME" \
    --from "$KEY_NAME" --keyring-backend test --chain-id "$CHAIN_ID" \
    --yes --gas auto --gas-adjustment 1.5 --home /Users/qianqi/.chain >/tmp/trnm_smoke_register.log 2>&1 || {
      cat /tmp/trnm_smoke_register.log
      exit 1
    }
  sleep 2
fi

echo "[4/6] Submit $COUNT jobs..."
"$ROOT/scripts/submit_jobs.sh" "$TASK_PATH" cpu "$COUNT" >/tmp/trnm_smoke_submit.log 2>&1 || {
  cat /tmp/trnm_smoke_submit.log
  exit 1
}

echo "[5/6] Wait for worker processing..."
# conservative wait: ~35s per job max
sleep $((COUNT * 35))

echo "[6/6] Verify commits in worker log..."
COMMITS=$(grep -c "result committed on-chain" "$WORKER_LOG" || true)
echo "Committed count in log: $COMMITS"
if [[ "$COMMITS" -lt "$COUNT" ]]; then
  echo "SMOKE FAILED: expected >=$COUNT commits"
  tail -n 200 "$WORKER_LOG"
  exit 2
fi

echo "SMOKE PASS ✅"
tail -n 80 "$WORKER_LOG"
