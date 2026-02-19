#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/build/chaind}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
WAIT_SEC="${WAIT_SEC:-20}"
TASK_PATH="${TASK_PATH:-$ROOT/tasks/example_futures}"
REQS="${REQS:-cpu}"

log() { printf "\n[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

workload_stats() {
  local attempt=0 out rc
  while (( attempt < 10 )); do
    set +e
    out="$($BIN query workload list-task -o json --node "$NODE" --home "$HOME_DIR" 2>/dev/null | python3 -c 'import json,sys; obj=json.load(sys.stdin); ids=[int(t.get("id",0)) for t in obj.get("Task",[]) if str(t.get("id","0")).isdigit()]; total=int(obj.get("pagination",{}).get("total",0)); print(f"{max(ids) if ids else 0} {total}")')"
    rc=$?
    set -e
    if [[ $rc -eq 0 && -n "$out" ]]; then
      echo "$out"
      return 0
    fi
    ((attempt++))
    sleep 0.8
  done
  return 1
}

latest_task_id() {
  workload_stats | awk '{print $1}'
}

latest_task_total() {
  workload_stats | awk '{print $2}'
}

task_status() {
  local task_id="$1" attempt=0 out rc
  while (( attempt < 6 )); do
    set +e
    out="$($BIN query workload show-task "$task_id" -o json --node "$NODE" --home "$HOME_DIR" 2>/dev/null | python3 -c 'import json,sys; obj=json.load(sys.stdin); print(int(obj.get("task",{}).get("status",0)))')"
    rc=$?
    set -e
    if [[ $rc -eq 0 && -n "$out" ]]; then
      echo "$out"
      return 0
    fi
    ((attempt++))
    sleep 0.6
  done
  return 1
}

log "Scenario B (Timeout): stop worker to emulate unprocessed task"
pkill -f "main.py start" >/dev/null 2>&1 || true
rm -f "$ROOT/worker/.worker.lock"

before_id=$(latest_task_id)
before_total=$(latest_task_total)
log "Latest task before submit: id=$before_id total=$before_total"

current_seq() {
  local addr
  addr="$($BIN keys show bob -a --keyring-backend test --home "$HOME_DIR")"
  "$BIN" query auth account "$addr" -o json --node "$NODE" --home "$HOME_DIR" \
    | python3 -c 'import json,sys;o=json.load(sys.stdin);a=o.get("account",{});print(a.get("sequence") or a.get("base_account",{}).get("sequence") or 0)'
}

submit_ok=0
seq_override=""
for _ in {1..20}; do
  if [[ -n "$seq_override" ]]; then
    seq="$seq_override"
  else
    seq="$(current_seq || echo 0)"
  fi

  set +e
  SUBMIT_OUT="$($BIN tx workload create-task "$TASK_PATH" 0 0 "" "" \
    --from bob --keyring-backend test --chain-id "$CHAIN_ID" \
    --node "$NODE" --home "$HOME_DIR" --sequence "$seq" --yes --gas auto --gas-adjustment 1.5 -o json 2>&1)"
  SUBMIT_RC=$?
  set -e
  if [[ $SUBMIT_RC -eq 0 ]] && grep -q '"code":0' <<<"${SUBMIT_OUT// /}"; then
    submit_ok=1
    break
  fi
  if grep -qi "account sequence mismatch" <<<"$SUBMIT_OUT"; then
    seq_override="$(echo "$SUBMIT_OUT" | sed -n 's/.*expected \([0-9][0-9]*\), got.*/\1/p' | head -n1)"
    sleep 1.2
    continue
  fi
  echo "$SUBMIT_OUT"
  exit 1
done
if [[ $submit_ok -ne 1 ]]; then
  echo "$SUBMIT_OUT"
  exit 1
fi

after_id="$before_id"
after_total="$before_total"
for _ in 1 2 3 4 5 6 7 8; do
  sleep 0.9
  after_total=$(latest_task_total || echo "$before_total")
  after_id=$(latest_task_id || echo "$before_id")
  if [[ "$after_total" -gt "$before_total" || "$after_id" -gt "$before_id" ]]; then
    break
  fi
done
if [[ "$after_total" -le "$before_total" && "$after_id" -le "$before_id" ]]; then
  echo "❌ No new task detected after submit (id=$after_id total=$after_total)"
  exit 1
fi

log "New task id: $after_id; waiting ${WAIT_SEC}s"
sleep "$WAIT_SEC"

status=$(task_status "$after_id")
log "Task $after_id status after wait: $status"
# canonical mapping in proto: 0 OPEN, 1 ASSIGNED, 2 COMMITTED, 3 REVEALED, ...
if [[ "$status" -ge 2 ]]; then
  echo "❌ Scenario B failed: task progressed unexpectedly (status=$status)"
  exit 1
fi

echo "✅ Scenario B passed: task remained uncommitted with worker offline"
