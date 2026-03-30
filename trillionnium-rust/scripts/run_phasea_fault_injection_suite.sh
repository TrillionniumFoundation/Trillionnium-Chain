#!/usr/bin/env bash
set -u -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health/phasea-fault-suite-$TS}"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"

PASS=0
FAIL=0

record_case() {
  local name="$1"
  local status="$2"
  local log="$3"
  local reason="${4:-}"
  if [[ "$status" == "PASS" ]]; then
    PASS=$((PASS+1))
    echo "$name=PASS log=$log" >> "$SUMMARY"
  else
    FAIL=$((FAIL+1))
    echo "$name=FAIL reason=${reason:-unknown} log=$log" >> "$SUMMARY"
  fi
}

run_sqlite_lock_conflict_short() {
  local name="sqlite_lock_conflict_short"
  local log="$OUT_DIR/${name}.log"
  local db="$OUT_DIR/sqlite-lock-conflict.sqlite"

  {
    echo "[case] $name"
    python3 - <<'PY' "$db"
import sqlite3
import sys
import threading
import time

path = sys.argv[1]

seed = sqlite3.connect(path, timeout=0.0)
seed.execute("CREATE TABLE IF NOT EXISTS t(x INTEGER)")
seed.commit()
seed.close()

ready = threading.Event()
result = {"ok": False, "err": ""}

def lock_holder():
    holder = sqlite3.connect(path, timeout=0.0)
    holder.execute("BEGIN EXCLUSIVE")
    holder.execute("INSERT INTO t(x) VALUES(1)")
    ready.set()
    time.sleep(0.6)
    holder.rollback()
    holder.close()

def contender():
    ready.wait(2)
    c = sqlite3.connect(path, timeout=0.0)
    try:
        c.execute("INSERT INTO t(x) VALUES(2)")
        c.commit()
    except Exception as e:
        result["err"] = str(e)
    else:
        result["ok"] = True
    finally:
        c.close()

t1 = threading.Thread(target=lock_holder)
t2 = threading.Thread(target=contender)
t1.start(); t2.start(); t1.join(); t2.join()

if result["ok"]:
    raise SystemExit("expected lock conflict but contender succeeded")
if "locked" not in result["err"].lower() and "busy" not in result["err"].lower():
    raise SystemExit(f"unexpected contender error: {result['err']}")
print("[OK] sqlite lock conflict observed:", result["err"])
PY
  } > >(tee "$log") 2>&1
}

run_sqlite_unwritable() {
  local name="sqlite_unwritable"
  local log="$OUT_DIR/${name}.log"
  local dir="$OUT_DIR/sqlite-unwritable"

  {
    echo "[case] $name"
    rm -rf "$dir"
    mkdir -p "$dir"
    chmod 500 "$dir"
    set +e
    python3 - <<'PY' "$dir"
import sqlite3
import sys
from pathlib import Path

d = Path(sys.argv[1])
db = d / "db.sqlite"
conn = sqlite3.connect(str(db), timeout=0.0)
conn.execute("CREATE TABLE x(a INTEGER)")
conn.commit()
conn.close()
print("unexpectedly writable")
PY
    rc=$?
    set -e
    chmod 700 "$dir"

    if [[ $rc -eq 0 ]]; then
      echo "[FAIL] expected sqlite open/write to fail on unwritable path"
      return 1
    fi
    echo "[OK] sqlite unwritable path rejected writes"
  } > >(tee "$log") 2>&1
}

run_worker_interrupt_recovery() {
  local name="worker_interrupt_recovery"
  local log="$OUT_DIR/${name}.log"
  local state="$OUT_DIR/worker-resume-state.json"
  local submit_log="$OUT_DIR/worker-resume-submits.jsonl"
  local ack_log="$OUT_DIR/worker-resume-acks.jsonl"
  local out_json="$OUT_DIR/worker-resume-runonce.json"
  local adapter_partial="$OUT_DIR/worker-partial-adapter.sh"

  {
    echo "[case] $name"

    rm -f "$state" "$submit_log" "$ack_log" "$out_json" "$adapter_partial"
    local start_id
    start_id=$(( $(date +%s%N) / 1000 ))
    printf '{"last_task_id": %s}\n' "$start_id" > "$state"

    cat > "$adapter_partial" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
kind="${1:-}"
if [[ "$kind" == "commit" ]]; then
  ./scripts/worker_tx_adapter.sh "$@"
  exit 0
fi
echo "[adapter] simulated reveal transport failure"
exit 42
EOF
    chmod +x "$adapter_partial"

    cargo run -q -p trnm-worker-agent -- run-once \
      --state "$state" \
      --worker worker1 \
      --payload "demo-payload-resume" \
      --submit \
      --submit-log "$submit_log" > "$out_json"

    cargo run -q -p trnm-worker-agent -- flush-submissions \
      --submit-log "$submit_log" \
      --execute \
      --adapter-cmd "$adapter_partial" \
      --max-retries 0 \
      --ack-log "$ack_log" > "$OUT_DIR/worker-resume-pass1.out"

    cargo run -q -p trnm-worker-agent -- flush-submissions \
      --submit-log "$submit_log" \
      --execute \
      --adapter-cmd "./scripts/worker_tx_adapter.sh" \
      --max-retries 0 \
      --ack-log "$ack_log" > "$OUT_DIR/worker-resume-pass2.out"

    TASK_ID="$(python3 - <<'PY' "$out_json"
import json,sys
print(json.load(open(sys.argv[1]))['task_id'])
PY
)"

    python3 - <<'PY' "$ack_log" "$TASK_ID"
import json,sys
ack_path, task_id = sys.argv[1], int(sys.argv[2])
rows = []
with open(ack_path) as f:
    for line in f:
        line = line.strip()
        if line:
            rows.append(json.loads(line))
rows = [r for r in rows if r.get('task_id') == task_id]
assert rows, f'no ack for task_id={task_id}'
statuses = [r.get('status') for r in rows]
assert ('failed' in statuses) or ('rejected' in statuses), f'expected failed/rejected status, got {statuses}'
assert 'accepted' in statuses, f'expected accepted status after resume, got {statuses}'
print('[OK] worker interruption recovery validated task_id=%s statuses=%s' % (task_id, statuses))
PY
  } > >(tee "$log") 2>&1
}

run_node_restart_recovery() {
  local name="node_restart_recovery"
  local log="$OUT_DIR/${name}.log"

  {
    echo "[case] $name"
    local recovery_env=(RUNS="${RUNS:-3}")
    if [[ -n "${EXPECTED_WORKTREE_ROOT:-}" ]]; then
      recovery_env+=(EXPECTED_WORKTREE_ROOT="$EXPECTED_WORKTREE_ROOT")
    fi
    if [[ -n "${EXPECTED_BRANCH_REF:-}" ]]; then
      recovery_env+=(EXPECTED_BRANCH_REF="$EXPECTED_BRANCH_REF")
    fi
    if [[ -n "${EXPECTED_HEAD:-}" ]]; then
      recovery_env+=(EXPECTED_HEAD="$EXPECTED_HEAD")
    fi
    env "${recovery_env[@]}" ./scripts/check_bft_restart_recovery.sh
    local latest
    latest="$(ls -t "$ROOT"/run/bft-restart-recovery-*.txt 2>/dev/null | head -n1 || true)"
    if [[ -z "$latest" ]]; then
      echo "[FAIL] missing bft restart recovery report"
      return 1
    fi
    if ! grep -q '^status=PASS$' "$latest"; then
      echo "[FAIL] restart recovery report not PASS: $latest"
      return 1
    fi
    echo "report=$latest"
    echo "[OK] node restart recovery PASS"
  } > >(tee "$log") 2>&1
}

echo "phasea_fault_suite.ts=$TS" > "$SUMMARY"
echo "phasea_fault_suite.out_dir=$OUT_DIR" >> "$SUMMARY"
echo "cases:" >> "$SUMMARY"

for case in sqlite_lock_conflict_short sqlite_unwritable worker_interrupt_recovery node_restart_recovery; do
  fn="run_${case}"
  log="$OUT_DIR/${case}.log"
  if "$fn"; then
    record_case "$case" "PASS" "$log"
  else
    record_case "$case" "FAIL" "$log" "case_execution_error"
  fi
done

echo "pass_count=$PASS" >> "$SUMMARY"
echo "fail_count=$FAIL" >> "$SUMMARY"
if [[ $FAIL -eq 0 ]]; then
  echo "result=PASS" >> "$SUMMARY"
else
  echo "result=FAIL" >> "$SUMMARY"
fi

echo "summary=$SUMMARY"
if [[ $FAIL -eq 0 ]]; then
  echo "[OK] phaseA fault injection suite passed"
  exit 0
else
  echo "[FAIL] phaseA fault injection suite failed" >&2
  exit 1
fi
