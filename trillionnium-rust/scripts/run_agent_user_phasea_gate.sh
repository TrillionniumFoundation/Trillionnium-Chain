#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/run/health}"
OUT="$OUT_DIR/agent-user-phasea-gate-$TS.txt"
mkdir -p "$OUT_DIR" "$ROOT/run/message-gateway"

# Reliability store selection for gate smoke.
# RELIABILITY_STORE: sqlite (default, production) | memory
# RELIABILITY_DB_PATH: sqlite file path override when RELIABILITY_STORE=sqlite
RELIABILITY_STORE="${RELIABILITY_STORE:-sqlite}"
RELIABILITY_DB_PATH="${RELIABILITY_DB_PATH:-$OUT_DIR/reliability-phasea.sqlite}"

INGRESS="$ROOT/run/message-gateway/requests.jsonl"
BACKUP="$ROOT/run/message-gateway/requests.backup-$TS.jsonl"
SUBMIT_LOG="/tmp/trnm-worker-agent-submissions-phasea-$TS.jsonl"

if [[ -f "$INGRESS" ]]; then
  cp "$INGRESS" "$BACKUP"
fi
: > "$INGRESS"
: > "$SUBMIT_LOG"

cleanup() {
  if [[ -f "$BACKUP" ]]; then
    mv "$BACKUP" "$INGRESS"
  else
    rm -f "$INGRESS"
  fi
}
trap cleanup EXIT

chmod +x ./scripts/llm_adapter_mock.sh

{
  echo "[phaseA] cargo test trnm-rpc + trnm-worker-agent"
  cargo test -q -p trnm-rpc -p trnm-worker-agent

  echo "[phaseA] gate: ack batch + retry circuit-breaker tests"
  cargo test -q -p trnm-rpc relay_ack_upto_seq_batch_and_boundaries
  cargo test -q -p trnm-rpc circuit_breaker_opens_and_recovers_after_window

  echo "[phaseA] gate: relay proof smoke + tamper matrix"
  cargo test -q -p trnm-rpc relay_session_proof_smoke_and_tamper_matrix

  if [[ "$RELIABILITY_STORE" == "sqlite" ]]; then
    rm -f "$RELIABILITY_DB_PATH"
    echo "[phaseA] gate: reliability persistent sqlite smoke"
    RELIABILITY_STORE=sqlite RELIABILITY_DB_PATH="$RELIABILITY_DB_PATH" \
      cargo test -q -p trnm-rpc reliability_persistent_store_smoke -- --nocapture
    if [[ ! -f "$RELIABILITY_DB_PATH" ]]; then
      echo "[FAIL] expected sqlite db created at $RELIABILITY_DB_PATH" >&2
      exit 4
    fi
    echo "reliability_store=sqlite"
    echo "reliability_db_path=$RELIABILITY_DB_PATH"
  else
    echo "[phaseA] gate: reliability persistent sqlite smoke (skip, RELIABILITY_STORE=$RELIABILITY_STORE)"
  fi

  echo "[phaseA] rpc submit-message"
  submit_json="$(cargo run -q -p trnm-rpc -- submit-message \
    --channel telegram \
    --user-id phasea-user \
    --session-id phasea-sid-$TS \
    --text "phaseA gate smoke" \
    --idempotency-key phasea-ikey-$TS)"

  request_id="$(python3 - <<'PY' "$submit_json"
import json,sys
print(json.loads(sys.argv[1])["request_id"])
PY
)"

  echo "[phaseA] rpc dispatch-open"
  cargo run -q -p trnm-rpc -- dispatch-open --worker-id worker-1 --limit 1 >/dev/null

  echo "[phaseA] worker run-assigned"
  cargo run -q -p trnm-worker-agent -- run-assigned \
    --worker worker-1 \
    --ingress-file "$INGRESS" \
    --limit 1 \
    --submit-log "$SUBMIT_LOG" \
    --llm-adapter-cmd ./scripts/llm_adapter_mock.sh >/dev/null

  echo "[phaseA] rpc query-request-full"
  full="$(cargo run -q -p trnm-rpc -- query-request-full --request-id "$request_id")"

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

  echo "request_id=$request_id"
  echo "status=$status"
  echo "verifier_status=$verifier"

  if [[ "$status" != "COMMIT_QUEUED" ]]; then
    echo "[FAIL] expected status=COMMIT_QUEUED, got $status" >&2
    exit 2
  fi
  if [[ "$verifier" != "accepted" ]]; then
    echo "[FAIL] expected verifier_status=accepted, got $verifier" >&2
    exit 3
  fi

  echo "status=PASS"
  echo "[OK] agent-user phaseA gate passed"
} | tee "$OUT"

echo "[OK] phaseA gate report: $OUT"
