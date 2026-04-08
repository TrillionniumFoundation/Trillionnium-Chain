#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/request-fault-injection-$TS.txt"

INGRESS_REAL="$ROOT/run/message-gateway/requests.jsonl"
BACKUP_INGRESS="$ROOT/run/message-gateway/requests.backup-$TS.jsonl"
SUBMIT_LOG="/tmp/trnm-worker-agent-submissions-fault-$TS.jsonl"
mkdir -p "$ROOT/run/message-gateway"
if [[ -f "$INGRESS_REAL" ]]; then
  cp "$INGRESS_REAL" "$BACKUP_INGRESS"
fi
: > "$INGRESS_REAL"
: > "$SUBMIT_LOG"
cleanup() {
  if [[ -f "$BACKUP_INGRESS" ]]; then
    mv "$BACKUP_INGRESS" "$INGRESS_REAL"
  else
    rm -f "$INGRESS_REAL"
  fi
}
trap cleanup EXIT

case_run() {
  local name="$1"
  local adapter="$2"
  local text="$3"

  : > "$INGRESS_REAL"

  local sid="fault-$name-$TS"
  local ikey="ikey-$name-$TS"

  cargo run -q -p trnm-rpc -- submit-message \
    --channel telegram \
    --user-id test-user \
    --session-id "$sid" \
    --text "$text" \
    --idempotency-key "$ikey" >/tmp/fault-submit-$name.json

  local req_id
  req_id="$(python3 - <<PY
import json
p='/tmp/fault-submit-${name}.json'
print(json.load(open(p))['request_id'])
PY
)"

  cargo run -q -p trnm-rpc -- dispatch-open --worker-id worker-1 --limit 1 >/dev/null

  set +e
  cargo run -q -p trnm-worker-agent -- run-assigned \
    --worker worker-1 \
    --ingress-file run/message-gateway/requests.jsonl \
    --limit 1 \
    --submit-log "$SUBMIT_LOG" \
    --llm-adapter-cmd "$adapter" \
    --verifier-max-output-chars 80 >"/tmp/fault-run-$name.log" 2>&1
  rc=$?
  set -e

  local full
  full="$(cargo run -q -p trnm-rpc -- query-request-full --request-id "$req_id")"
  local status verifier reason
  status="$(FULL_JSON="$full" python3 - <<'PY'
import json,os
obj=json.loads(os.environ['FULL_JSON'])
print(obj['request']['status'])
PY
)"
  verifier="$(FULL_JSON="$full" python3 - <<'PY'
import json,os
obj=json.loads(os.environ['FULL_JSON'])
print(obj.get('verifier_status'))
PY
)"
  reason="$(FULL_JSON="$full" python3 - <<'PY'
import json,os
obj=json.loads(os.environ['FULL_JSON'])
print(obj.get('resolution_code'))
PY
)"

  {
    echo "case=$name"
    echo "adapter=$adapter"
    echo "request_id=$req_id"
    echo "run_assigned_rc=$rc"
    echo "status=$status"
    echo "verifier_status=$verifier"
    echo "resolution_code=$reason"
    echo "---"
  } >> "$OUT"
}

chmod +x ./scripts/llm_adapter_mock.sh ./scripts/llm_adapter_invalid_json.sh ./scripts/llm_adapter_timeout.sh ./scripts/llm_adapter_echo.sh

case_run ok ./scripts/llm_adapter_mock.sh "正常请求"
case_run invalid_json ./scripts/llm_adapter_invalid_json.sh "坏JSON"
case_run too_long ./scripts/llm_adapter_echo.sh "$(python3 - <<'PY'
print('A'*5000)
PY
)"

{
  echo "summary_file=$OUT"
  echo "done=true"
} >> "$OUT"

echo "[OK] request fault injection report: $OUT"