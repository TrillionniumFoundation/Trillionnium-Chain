#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

AGENTS="${AGENTS:-3}"
REAL_CLI="${TRNM_TX_CLI:-}"
SKIP_GATES="${SKIP_GATES:-0}"
PARALLEL_SUBMIT="${PARALLEL_SUBMIT:-1}"
MAX_PARALLEL="${MAX_PARALLEL:-8}"

usage() {
  cat <<EOF
Usage:
  AGENTS=3 ./scripts/v2/worker_agent_mining_onboard.sh
  TRNM_TX_CLI=./trillionnium/target/debug/trnm-cli ./scripts/v2/worker_agent_mining_onboard.sh
  SKIP_GATES=1 AGENTS=5 ./scripts/v2/worker_agent_mining_onboard.sh

Env:
  AGENTS           Number of worker identities for multi-agent smoke (default: 3)
  TRNM_TX_CLI      Real tx CLI path/name (optional). If set, real-cli gates are used.
  SKIP_GATES       1 to skip gate stage and run multi-agent smoke only.
  PARALLEL_SUBMIT  1 to submit run-once concurrently (default: 1)
  MAX_PARALLEL     Max concurrent run-once jobs when PARALLEL_SUBMIT=1 (default: 8)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

RUN_TAG="$(date +%Y%m%d-%H%M%S)-$$"
OUT_DIR="$ROOT/data/worker-onboard/$RUN_TAG"
mkdir -p "$OUT_DIR"

SUBMIT_LOG="$OUT_DIR/submits.jsonl"
ACK_LOG="$OUT_DIR/acks.jsonl"
EVENT_LOG="$OUT_DIR/events.jsonl"
PROGRESS_LOG="$OUT_DIR/progress.jsonl"
SUMMARY_JSON="$OUT_DIR/summary.json"
SUBMIT_TMP_DIR="$OUT_DIR/submit-parts"
SUBMIT_RUN_LOG_DIR="$OUT_DIR/submit-run-logs"
mkdir -p "$SUBMIT_TMP_DIR" "$SUBMIT_RUN_LOG_DIR"

# Every onboarding run owns its adapter receipt journal. Reusing the adapter's
# date-based default makes a later hermetic smoke look like a replay of an
# earlier run because the deterministic task ranges intentionally repeat.
: "${TRNM_TX_ADAPTER_OUT_LOG:=$OUT_DIR/tx-adapter.jsonl}"
export TRNM_TX_ADAPTER_OUT_LOG

if [[ "$SKIP_GATES" != "1" ]]; then
  if [[ -n "$REAL_CLI" ]]; then
    echo "[stage] run real-cli worker receipt gates"
    TRNM_TX_CLI="$REAL_CLI" ./scripts/v2/run_worker_receipt_gates_real_cli.sh
  else
    echo "[stage] run worker receipt gates"
    ./scripts/v2/run_worker_receipt_gates.sh
  fi
fi

cd "$ROOT/trillionnium"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[stage] multi-agent smoke: agents=$AGENTS parallel_submit=$PARALLEL_SUBMIT max_parallel=$MAX_PARALLEL"
submit_start_ms=$(python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
)

if [[ "$PARALLEL_SUBMIT" == "1" ]]; then
  pids=()
  workers=()
  for i in $(seq 1 "$AGENTS"); do
    worker="worker${i}"
    part_log="$SUBMIT_TMP_DIR/${worker}.jsonl"
    run_log="$SUBMIT_RUN_LOG_DIR/${worker}.log"
    state_file="/tmp/trnm-worker-agent-state-${RUN_TAG}-${worker}.json"
    # ensure per-worker unique task id range when running in parallel
    seed=$((1000 + i * 100000))
    printf '{"last_task_id": %s}\n' "$seed" > "$state_file"

    (
      cargo run -q -p trnm-worker-agent -- run-once \
        --state "$state_file" \
        --worker "$worker" \
        --payload "demo-payload-${i}" \
        --submit \
        --submit-log "$part_log" >"$run_log" 2>&1
    ) &

    pids+=("$!")
    workers+=("$worker")

    while [[ "${#pids[@]}" -ge "$MAX_PARALLEL" ]]; do
      finished=false
      for idx in "${!pids[@]}"; do
        pid="${pids[$idx]}"
        if ! kill -0 "$pid" 2>/dev/null; then
          wait "$pid"
          unset 'pids[idx]'
          unset 'workers[idx]'
          pids=("${pids[@]}")
          workers=("${workers[@]}")
          finished=true
          break
        fi
      done
      if [[ "$finished" == false ]]; then
        sleep 0.05
      fi
    done
  done

  submit_failed=0
  for idx in "${!pids[@]}"; do
    if ! wait "${pids[$idx]}"; then
      echo "[FAIL] submit failed: ${workers[$idx]} (log=$SUBMIT_RUN_LOG_DIR/${workers[$idx]}.log)" >&2
      submit_failed=1
    fi
  done

  if [[ "$submit_failed" -ne 0 ]]; then
    echo "[FAIL] one or more parallel submit jobs failed" >&2
    exit 24
  fi

  # merge per-worker submit logs deterministically
  : > "$SUBMIT_LOG"
  for i in $(seq 1 "$AGENTS"); do
    worker="worker${i}"
    part_log="$SUBMIT_TMP_DIR/${worker}.jsonl"
    if [[ -f "$part_log" ]]; then
      cat "$part_log" >> "$SUBMIT_LOG"
      echo "  - submitted $worker"
    else
      echo "[FAIL] missing submit part log for $worker" >&2
      exit 25
    fi
  done
else
  STATE_FILE="/tmp/trnm-worker-agent-state-${RUN_TAG}.json"
  for i in $(seq 1 "$AGENTS"); do
    cargo run -q -p trnm-worker-agent -- run-once \
      --state "$STATE_FILE" \
      --worker "worker${i}" \
      --payload "demo-payload-${i}" \
      --submit \
      --submit-log "$SUBMIT_LOG" >/dev/null
    echo "  - submitted worker${i}"
  done
fi

submit_end_ms=$(python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
)

flush_start_ms=$(python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
)

cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --execute \
  --adapter-cmd "./scripts/worker_tx_adapter.sh" \
  --ack-log "$ACK_LOG" \
  --event-log "$EVENT_LOG" \
  --progress-log "$PROGRESS_LOG" >/dev/null

flush_end_ms=$(python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
)

python3 - <<'PY' "$AGENTS" "$ACK_LOG" "$SUMMARY_JSON" "$submit_start_ms" "$submit_end_ms" "$flush_start_ms" "$flush_end_ms" "$PARALLEL_SUBMIT" "$MAX_PARALLEL"
import json, sys
agents = int(sys.argv[1])
ack_log = sys.argv[2]
out = sys.argv[3]
submit_start_ms = int(sys.argv[4])
submit_end_ms = int(sys.argv[5])
flush_start_ms = int(sys.argv[6])
flush_end_ms = int(sys.argv[7])
parallel_submit = sys.argv[8] == '1'
max_parallel = int(sys.argv[9])
accepted = rejected = failed = 0
rows = []
with open(ack_log, 'r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        obj=json.loads(line)
        rows.append(obj)
        s=obj.get('status')
        if s=='accepted': accepted += 1
        elif s=='rejected': rejected += 1
        elif s=='failed': failed += 1
terminal = accepted + rejected
task_ids = [row.get('task_id') for row in rows]
unique_task_ids = len(set(task_ids))
valid_task_ids = all(
    isinstance(task_id, int) and not isinstance(task_id, bool) and task_id >= 0
    for task_id in task_ids
)
submit_elapsed_ms = max(0, submit_end_ms - submit_start_ms)
flush_elapsed_ms = max(0, flush_end_ms - flush_start_ms)
total_elapsed_ms = max(0, flush_end_ms - submit_start_ms)
submit_tps = (agents * 1000.0 / submit_elapsed_ms) if submit_elapsed_ms > 0 else None
flush_tps = (len(rows) * 1000.0 / flush_elapsed_ms) if flush_elapsed_ms > 0 else None
end2end_tps = (agents * 1000.0 / total_elapsed_ms) if total_elapsed_ms > 0 else None
summary = {
    'agents': agents,
    'acks_total': len(rows),
    'unique_task_ids': unique_task_ids,
    'accepted': accepted,
    'rejected': rejected,
    'failed': failed,
    'terminal': terminal,
    'parallel_submit': parallel_submit,
    'max_parallel': max_parallel,
    'timing': {
        'submit_elapsed_ms': submit_elapsed_ms,
        'flush_elapsed_ms': flush_elapsed_ms,
        'total_elapsed_ms': total_elapsed_ms,
    },
    'throughput': {
        'submit_tasks_per_sec': round(submit_tps, 3) if submit_tps is not None else None,
        'flush_acks_per_sec': round(flush_tps, 3) if flush_tps is not None else None,
        'end2end_tasks_per_sec': round(end2end_tps, 3) if end2end_tps is not None else None,
    },
    'ok': (
        len(rows) == agents
        and accepted == agents
        and rejected == 0
        and failed == 0
        and valid_task_ids
        and unique_task_ids == agents
    )
}
with open(out, 'w', encoding='utf-8') as w:
    json.dump(summary, w, indent=2, ensure_ascii=False)
print(json.dumps(summary, ensure_ascii=False))
if not summary['ok']:
    raise SystemExit(23)
PY

cat <<EOF
[OK] worker-agent onboarding completed
- run_tag: $RUN_TAG
- out_dir: $OUT_DIR
- submit_log: $SUBMIT_LOG
- ack_log: $ACK_LOG
- summary: $SUMMARY_JSON
EOF
