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
NODE="${NODE:-tcp://127.0.0.1:26657}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"

latest_task_id() {
  "$BIN" query workload list-task -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c 'import json,sys;o=json.load(sys.stdin);ids=[int(t.get("id",0)) for t in o.get("Task",[]) if str(t.get("id","0")).isdigit()];print(max(ids) if ids else 0)'
}

task_status() {
  local id="$1"
  "$BIN" query workload show-task "$id" -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c 'import json,sys;o=json.load(sys.stdin);t=o.get("task") or o.get("Task") or {};print(int(t.get("status",0)))'
}

echo "[1/7] Ensure chain is running..."
$BIN status --node "$NODE" >/dev/null

echo "[2/7] Ensure single worker instance..."
pkill -f "main.py start" || true
rm -f "$WORKER_DIR/.worker.lock"
rm -f "$WORKER_DIR/worker_state.json"
: > "$WORKER_LOG"
(
  cd "$WORKER_DIR"
  nohup python3 main.py start > worker.log 2>&1 &
)

echo "[3/7] Wait worker listener ready..."
ready=0
for _ in {1..25}; do
  if grep -q "Synced at block height" "$WORKER_LOG" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "SMOKE FAILED: worker listener not ready"
  tail -n 120 "$WORKER_LOG" || true
  exit 2
fi
# avoid race: let subscriptions settle
sleep 3

echo "[4/7] Ensure worker is registered in workload module..."
WORKER_ADDR=$($BIN keys show "$KEY_NAME" -a --keyring-backend test --home "$HOME_DIR")
if ! $BIN query workload show-worker "$WORKER_ADDR" --node "$NODE" --home "$HOME_DIR" >/dev/null 2>&1; then
  echo "Worker $WORKER_ADDR not registered, registering now..."
  $BIN tx workload register-worker "$KEY_NAME" "ipfs://worker-$KEY_NAME" \
    --from "$KEY_NAME" --keyring-backend test --chain-id "$CHAIN_ID" --node "$NODE" \
    --yes --gas auto --gas-adjustment 1.5 --home "$HOME_DIR" >/tmp/trnm_smoke_register.log 2>&1 || {
      cat /tmp/trnm_smoke_register.log
      exit 1
    }
  sleep 2
fi

before_id=$(latest_task_id)
echo "[5/7] Submit $COUNT jobs... (before_id=$before_id)"
"$ROOT/scripts/submit_jobs.sh" "$TASK_PATH" cpu "$COUNT" >/tmp/trnm_smoke_submit.log 2>&1 || {
  cat /tmp/trnm_smoke_submit.log
  exit 1
}

after_id="$before_id"
for _ in {1..10}; do
  after_id=$(latest_task_id || echo "$before_id")
  if [[ "$after_id" -ge $((before_id + COUNT)) ]]; then
    break
  fi
  sleep 1
done
echo "Detected after_id=$after_id"

poll_progress() {
  local need="$1" max_wait="$2" elapsed=0
  while (( elapsed < max_wait )); do
    COMMITS=$(grep -c "result committed on-chain" "$WORKER_LOG" || true)
    chain_ok=0
    for id in $(seq $((before_id + 1)) $((before_id + need))); do
      s=$(task_status "$id" 2>/dev/null || echo 0)
      if [[ "$s" -ge 2 ]]; then
        ((chain_ok+=1))
      fi
    done
    if [[ "$COMMITS" -ge "$need" || "$chain_ok" -ge "$need" ]]; then
      return 0
    fi
    sleep 3
    ((elapsed+=3))
  done
  return 1
}

echo "[6/7] Poll worker+chain progress..."
if ! poll_progress "$COUNT" $((COUNT * 45)); then
  echo "No progress yet; retrying once with worker restart + resubmit"
  pkill -f "main.py start" || true
  rm -f "$WORKER_DIR/.worker.lock"
  (
    cd "$WORKER_DIR"
    nohup python3 main.py start > worker.log 2>&1 &
  )
  sleep 5
  "$ROOT/scripts/submit_jobs.sh" "$TASK_PATH" cpu "$COUNT" >/tmp/trnm_smoke_submit_retry.log 2>&1 || true
  poll_progress "$COUNT" $((COUNT * 45)) || true
fi

echo "[7/7] Verify commits in worker log + chain..."
COMMITS=$(grep -c "result committed on-chain" "$WORKER_LOG" || true)
chain_ok=0
for id in $(seq $((before_id + 1)) $((before_id + COUNT))); do
  s=$(task_status "$id" 2>/dev/null || echo 0)
  echo "task $id status=$s"
  if [[ "$s" -ge 2 ]]; then
    ((chain_ok+=1))
  fi
done

echo "Committed count in log: $COMMITS"
echo "Committed-or-later on chain: $chain_ok/$COUNT"
if [[ "$COMMITS" -lt "$COUNT" && "$chain_ok" -lt "$COUNT" ]]; then
  echo "SMOKE FAILED: expected >=$COUNT commits (log or chain)"
  tail -n 200 "$WORKER_LOG"
  [[ -f /tmp/trnm_smoke_submit_retry.log ]] && { echo "--- retry submit log ---"; cat /tmp/trnm_smoke_submit_retry.log; }
  exit 2
fi

echo "SMOKE PASS ✅"
tail -n 80 "$WORKER_LOG"
