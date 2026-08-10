#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

pick_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    command -v cargo
    return
  fi
  if [[ -x "$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo" ]]; then
    echo "$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo"
    return
  fi
  echo "cargo not found (checked PATH and rustup toolchain path)" >&2
  exit 127
}

CARGO_BIN="$(pick_cargo)"
export PATH="$(dirname "$CARGO_BIN"):$PATH"
RUN_TAG="$(date +%Y%m%d-%H%M%S)-$$"

STATE="${BOUNDARY_STATE:-/tmp/trnm-worker-boundary-state-${RUN_TAG}.json}"
SUBMIT_LOG="${BOUNDARY_SUBMIT_LOG:-/tmp/trnm-worker-boundary-submits-${RUN_TAG}.jsonl}"
ACK_LOG="${BOUNDARY_ACK_LOG:-/tmp/trnm-worker-boundary-acks-${RUN_TAG}.jsonl}"
OUT_LOG="${BOUNDARY_TX_ADAPTER_OUT_LOG:-/tmp/trnm-worker-boundary-adapter-${RUN_TAG}.jsonl}"
ATTEMPT_FILE="/tmp/trnm-worker-boundary-attempt-${RUN_TAG}.txt"
OUT_JSON="/tmp/trnm-worker-boundary-runonce-${RUN_TAG}.json"
FLUSH_OUT="/tmp/trnm-worker-boundary-flush-${RUN_TAG}.out"
CLI_LOG="/tmp/trnm-worker-boundary-cli-${RUN_TAG}.log"
FIXTURE_TX_CLI="/tmp/trnm-worker-boundary-cli-${RUN_TAG}.sh"
EVENT_LOG="/tmp/trnm-worker-boundary-events-${RUN_TAG}.jsonl"
PROGRESS_LOG="/tmp/trnm-worker-boundary-progress-${RUN_TAG}.jsonl"

rm -f "$STATE" "$SUBMIT_LOG" "$ACK_LOG" "$OUT_LOG" "$OUT_JSON" \
  "$ATTEMPT_FILE" "$FLUSH_OUT" "$CLI_LOG" "$FIXTURE_TX_CLI" \
  "$EVENT_LOG" "$PROGRESS_LOG"

# Keep this hermetic state lane disjoint from earlier worker gates and from a
# real receipt backend that may already have accepted the historical task 1001.
START_ID="$(python3 - <<'PY'
import time
print(time.time_ns() // 1000)
PY
)"
printf '{"last_task_id": %s}\n' "$START_ID" > "$STATE"
export TRNM_WORKER_EVENT_LOG="$EVENT_LOG"
export TRNM_WORKER_PROGRESS_LOG="$PROGRESS_LOG"

"$CARGO_BIN" run -q -p trnm-worker-agent -- run-once \
  --state "$STATE" \
  --worker worker1 \
  --payload "demo-payload-boundary" \
  --submit \
  --submit-log "$SUBMIT_LOG" > "$OUT_JSON"

TASK_ID=$(python3 - <<'PY' "$OUT_JSON"
import json,sys
print(json.load(open(sys.argv[1]))['task_id'])
PY
)

FLAKY_ADAPTER="/tmp/trnm-worker-boundary-flaky-${RUN_TAG}.sh"
cat > "$FLAKY_ADAPTER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ATTEMPT_FILE="${ATTEMPT_FILE:?}"
if [[ "${1:-}" == "commit" ]]; then
  n=0
  [[ -f "$ATTEMPT_FILE" ]] && n=$(cat "$ATTEMPT_FILE")
  n=$((n+1))
  echo "$n" > "$ATTEMPT_FILE"
  if [[ "$n" -le 2 ]]; then
    echo "[adapter] injected transient commit failure attempt=$n" >&2
    exit 1
  fi
fi
exec ./scripts/worker_tx_adapter.sh "$@"
EOF
chmod +x "$FLAKY_ADAPTER"

cat > "$FIXTURE_TX_CLI" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${BOUNDARY_CLI_LOG:?}"

if [[ "${1:-}" != "tx" ]]; then
  echo "expected tx command" >&2
  exit 2
fi

case "${2:-}" in
  commit-result)
    [[ "$#" -eq 6 ]] || { echo "invalid commit-result argv" >&2; exit 2; }
    [[ "$3" =~ ^[0-9]+$ && -n "$4" && "$5" =~ ^[0-9a-f]{64}$ && "$6" == "$3" ]] || {
      echo "invalid commit-result payload" >&2
      exit 2
    }
    ;;
  reveal-result)
    [[ "$#" -eq 5 ]] || { echo "invalid reveal-result argv" >&2; exit 2; }
    [[ "$3" =~ ^[0-9]+$ && "$4" =~ ^[0-9a-f]{64}$ && "$5" =~ ^[0-9a-f]{64}$ ]] || {
      echo "invalid reveal-result payload" >&2
      exit 2
    }
    ;;
  *)
    echo "unexpected tx subcommand: ${2:-}" >&2
    exit 2
    ;;
esac

printf '%s\n' "$*" >> "$BOUNDARY_CLI_LOG"
printf 'tx_hash=%s\n' "$(printf '%s' "$*" | shasum -a 256 | awk '{print $1}')"
EOF
chmod +x "$FIXTURE_TX_CLI"

START_MS=$(python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
)
USING_FIXTURE_TX_CLI=0
DEFAULT_TX_CLI="${TRNM_TX_CLI:-}"
if [[ -z "$DEFAULT_TX_CLI" ]]; then
  DEFAULT_TX_CLI="$FIXTURE_TX_CLI"
  USING_FIXTURE_TX_CLI=1
fi
if [[ "$DEFAULT_TX_CLI" == ./* || "$DEFAULT_TX_CLI" == scripts/* ]]; then
  DEFAULT_TX_CLI="$ROOT/${DEFAULT_TX_CLI#./}"
fi

TRNM_TX_ADAPTER_MODE=command \
TRNM_TX_CLI="$DEFAULT_TX_CLI" \
TRNM_TX_ADAPTER_OUT_LOG="$OUT_LOG" \
BOUNDARY_CLI_LOG="$CLI_LOG" \
ATTEMPT_FILE="$ATTEMPT_FILE" \
"$CARGO_BIN" run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --execute \
  --adapter-cmd "$FLAKY_ADAPTER" \
  --ack-log "$ACK_LOG" > "$FLUSH_OUT"
END_MS=$(python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
)
ELAPSED=$((END_MS-START_MS))

set +e
TRNM_TX_ADAPTER_OUT_LOG="$OUT_LOG" ./scripts/worker_tx_adapter.sh commit "$TASK_ID" worker1 deadbeef "$TASK_ID" >/tmp/trnm-worker-boundary-replay-${RUN_TAG}.out 2>&1
RC_REPLAY=$?
TRNM_TX_ADAPTER_OUT_LOG="$OUT_LOG" ./scripts/worker_tx_adapter.sh commit "$((TASK_ID+1))" worker1 cafebabe "$((TASK_ID-1))" >/tmp/trnm-worker-boundary-nonce-${RUN_TAG}.out 2>&1
RC_NONCE=$?
set -e

python3 - <<'PY' "$ACK_LOG" "$ATTEMPT_FILE" "$ELAPSED" "$RC_REPLAY" "$RC_NONCE" "$TASK_ID" "$CLI_LOG" "$USING_FIXTURE_TX_CLI"
import json,sys
ack_log,attempt_file,elapsed,rc_replay,rc_nonce,task_id,cli_log,using_fixture=sys.argv[1:]
elapsed=int(elapsed)
rc_replay=int(rc_replay)
rc_nonce=int(rc_nonce)
using_fixture=int(using_fixture)
acks=[json.loads(x) for x in open(ack_log) if x.strip()]
rows=[r for r in acks if int(r.get('task_id',-1))==int(task_id)]
assert rows, f'no ack for task_id={task_id}'
last=rows[-1]
attempts=int(open(attempt_file).read().strip())
assert last.get('status') == 'accepted', f"expected accepted ack, got {last.get('status')}"
assert attempts == 3, f"expected 3 commit attempts, got {attempts}"
assert elapsed >= 350, f"elapsed too short for linear backoff, elapsed_ms={elapsed}"
assert rc_replay == 9, f"expected replay rc=9, got {rc_replay}"
assert rc_nonce == 10, f"expected nonce rc=10, got {rc_nonce}"
if using_fixture:
    calls=[line.strip().split() for line in open(cli_log) if line.strip()]
    assert len(calls) == 2, f"expected commit+reveal fixture calls, got {calls!r}"
    commit,reveal=calls
    assert commit[:3] == ['tx','commit-result',task_id], f"unexpected commit argv: {commit!r}"
    assert len(commit) == 6 and commit[3] == 'worker1' and commit[5] == task_id, f"unexpected commit payload: {commit!r}"
    assert reveal[:3] == ['tx','reveal-result',task_id], f"unexpected reveal argv: {reveal!r}"
    assert len(reveal) == 5, f"unexpected reveal payload: {reveal!r}"
print('[OK] worker retry+nonce boundary test passed task_id=%s attempts=%s elapsed_ms=%s rc_replay=%s rc_nonce=%s' % (
    task_id, attempts, elapsed, rc_replay, rc_nonce
))
PY

echo "[INFO] boundary artifacts: ack_log=$ACK_LOG out_log=$OUT_LOG cli_log=$CLI_LOG run_tag=$RUN_TAG"
