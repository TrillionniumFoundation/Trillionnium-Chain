#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/request-tx-binding-$TS.txt"
mkdir -p "$OUT_DIR"

INGRESS="$ROOT/run/message-gateway/requests.jsonl"
BACKUP="$ROOT/run/message-gateway/requests.backup-$TS.jsonl"
SUBMIT_LOG="/tmp/trnm-worker-agent-submissions-binding-$TS.jsonl"
ACK_LOG="/tmp/trnm-worker-agent-acks-binding-$TS.jsonl"
EVENT_LOG="/tmp/trnm-worker-agent-events-binding-$TS.jsonl"
PROGRESS_LOG="/tmp/trnm-worker-agent-progress-binding-$TS.jsonl"

mkdir -p "$ROOT/run/message-gateway"
if [[ -f "$INGRESS" ]]; then
  cp "$INGRESS" "$BACKUP"
fi
: > "$INGRESS"
: > "$SUBMIT_LOG"
: > "$ACK_LOG"
: > "$EVENT_LOG"
: > "$PROGRESS_LOG"

cleanup() {
  if [[ -f "$BACKUP" ]]; then
    mv "$BACKUP" "$INGRESS"
  else
    rm -f "$INGRESS"
  fi
}
trap cleanup EXIT

chmod +x ./scripts/llm_adapter_mock.sh ./scripts/worker_tx_adapter.sh

submit_json="$(cargo run -q -p trnm-rpc -- submit-message \
  --channel telegram \
  --user-id binding-user \
  --session-id binding-sid-$TS \
  --text "binding check" \
  --idempotency-key binding-ikey-$TS)"

request_id="$(python3 - <<'PY' "$submit_json"
import json,sys
print(json.loads(sys.argv[1])['request_id'])
PY
)"

cargo run -q -p trnm-rpc -- dispatch-open --worker-id worker-1 --limit 1 >/dev/null

cargo run -q -p trnm-worker-agent -- run-assigned \
  --worker worker-1 \
  --ingress-file "$INGRESS" \
  --limit 1 \
  --submit-log "$SUBMIT_LOG" \
  --llm-adapter-cmd ./scripts/llm_adapter_mock.sh >/dev/null

TRNM_TX_ADAPTER_OUT_LOG="/tmp/trnm-tx-adapter-binding-$TS.jsonl" \
cargo run -q -p trnm-worker-agent -- flush-submissions \
  --submit-log "$SUBMIT_LOG" \
  --ingress-file "$INGRESS" \
  --execute \
  --adapter-cmd ./scripts/worker_tx_adapter.sh \
  --ack-log "$ACK_LOG" \
  --event-log "$EVENT_LOG" \
  --progress-log "$PROGRESS_LOG" >/dev/null

full="$(TRNM_RPC_INGRESS_FILE="$INGRESS" cargo run -q -p trnm-rpc -- query-request-full --request-id "$request_id")"

status="$(FULL_JSON="$full" python3 - <<'PY'
import json,os
obj=json.loads(os.environ['FULL_JSON'])
print(obj['request']['status'])
PY
)"
commit_tx_hash="$(FULL_JSON="$full" python3 - <<'PY'
import json,os
obj=json.loads(os.environ['FULL_JSON'])
print(obj.get('commit_tx_hash'))
PY
)"
reveal_tx_hash="$(FULL_JSON="$full" python3 - <<'PY'
import json,os
obj=json.loads(os.environ['FULL_JSON'])
print(obj.get('reveal_tx_hash'))
PY
)"

{
  echo "request_id=$request_id"
  echo "status=$status"
  echo "commit_tx_hash=$commit_tx_hash"
  echo "reveal_tx_hash=$reveal_tx_hash"
} > "$OUT"

is_missing_hash() {
  local v
  v="$(printf '%s' "${1:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  [[ -z "$v" || "$v" == "none" || "$v" == "null" ]]
}

if is_missing_hash "$commit_tx_hash"; then
  echo "[FAIL] missing commit_tx_hash" >&2
  exit 2
fi
if is_missing_hash "$reveal_tx_hash"; then
  echo "[FAIL] missing reveal_tx_hash" >&2
  exit 3
fi

echo "status=PASS" >> "$OUT"
echo "[OK] request tx binding passed: $OUT"