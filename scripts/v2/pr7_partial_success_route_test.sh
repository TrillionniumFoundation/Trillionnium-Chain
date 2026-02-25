#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-pr7-partial-success-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

REPORT="$TMP/pr6-summary-critical.txt"
STATE="$TMP/state.json"
DEAD="$TMP/dead-letter.jsonl"
AUDIT="$TMP/audit.jsonl"
OUT="$TMP/out.log"

cat > "$REPORT" <<'EOF'
status=FAIL
alert_code=PR6_ALERT_RULES
alert_message=[PR6][FAIL] routing test critical
generated_at_utc=2026-02-24T00:00:00+00:00
rule.unresolved_challenges.status=FAIL
rule.unresolved_challenges.value=7
rule.forfeits_daily_increase.status=FAIL
rule.forfeits_daily_increase.value=101
rule.escrow_nonzero_hours.status=FAIL
rule.escrow_nonzero_hours.value=24.10
EOF

set +e
DRY_RUN=1 ALERT_NOTIFY_DRY_RUN_FAIL_CHANNELS=imessage \
python3 ./scripts/v2/pr7_alert_delivery.py \
  --report "$REPORT" \
  --primary-channel imessage \
  --backup-channel telegram \
  --state-file "$STATE" \
  --dead-letter-file "$DEAD" \
  --audit-file "$AUDIT" \
  --max-retries 1 >"$OUT" 2>&1
rc=$?
set -e

if [[ $rc -ne 0 ]]; then
  echo "[FAIL] expected rc=0 for partial_success, got rc=$rc"
  cat "$OUT"
  exit 1
fi

grep -q "\[PR7\]\[WARN\] partial_success" "$OUT"

if [[ -f "$DEAD" ]] && [[ -s "$DEAD" ]]; then
  echo "[FAIL] dead-letter should stay empty for partial_success"
  cat "$DEAD"
  exit 1
fi

grep -q '"channel": "imessage"' "$AUDIT"
grep -q '"ok": false' "$AUDIT"
grep -q '"channel": "telegram"' "$AUDIT"
grep -q '"ok": true' "$AUDIT"

echo "[OK] pr7 partial_success route does not dead-letter when backup delivers"
