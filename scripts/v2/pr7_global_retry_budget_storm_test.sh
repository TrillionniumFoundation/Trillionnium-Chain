#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REPORT="$TMP_DIR/summary.txt"
STATE1="$TMP_DIR/state1.json"
STATE2="$TMP_DIR/state2.json"
BUDGET_STATE="$TMP_DIR/retry-budget-state.json"
DLQ1="$TMP_DIR/dead1.jsonl"
DLQ2="$TMP_DIR/dead2.jsonl"
OUT1="$TMP_DIR/run1.log"
OUT2="$TMP_DIR/run2.log"

cat >"$REPORT" <<'EOF'
status=WARN
alert_code=PR6_ALERT_RULES
alert_message=storm budget regression
generated_at_utc=2026-02-24T00:00:00Z
rule.unresolved_challenges.status=WARN
rule.unresolved_challenges.value=9
rule.forfeits_daily_increase.status=WARN
rule.forfeits_daily_increase.value=90
rule.escrow_nonzero_hours.status=WARN
rule.escrow_nonzero_hours.value=24
EOF

run_sender() {
  local state_file="$1"
  local dlq_file="$2"
  local out_file="$3"
  python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
    --report "$REPORT" \
    --channel imessage \
    --state-file "$state_file" \
    --dead-letter-file "$dlq_file" \
    --audit-file "$TMP_DIR/audit.jsonl" \
    --dry-run \
    --dry-run-fail-channels imessage \
    --dry-run-simulate-failures 99 \
    --max-retries 8 \
    --base-backoff-ms 1 \
    --max-backoff-ms 2 \
    --global-retry-budget 3 \
    --global-retry-window-seconds 600 \
    --global-retry-budget-state-file "$BUDGET_STATE" \
    >"$out_file" 2>&1 || true
}

run_sender "$STATE1" "$DLQ1" "$OUT1" &
PID1=$!
run_sender "$STATE2" "$DLQ2" "$OUT2" &
PID2=$!
wait "$PID1"
wait "$PID2"

if ! grep -q "global retry budget exhausted" "$OUT1" && ! grep -q "global retry budget exhausted" "$OUT2"; then
  echo "[TEST][FAIL] expected at least one sender to hit global retry budget exhaustion" >&2
  cat "$OUT1" >&2
  cat "$OUT2" >&2
  exit 1
fi

used="$(python3 - "$BUDGET_STATE" <<'PY'
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    d=json.load(f)
print(int(d.get('retries_used',-1)))
PY
)"
if [[ "$used" -ne 3 ]]; then
  echo "[TEST][FAIL] expected retries_used=3, got $used" >&2
  cat "$BUDGET_STATE" >&2
  exit 1
fi

echo "[OK] pr7 global retry budget storm control regression passed"