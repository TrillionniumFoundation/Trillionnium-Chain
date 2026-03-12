#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-invalid-quiet-hours.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

REPORT="$TMP/summary.txt"
cat >"$REPORT" <<'EOF'
status=WARN
alert_code=PR6_ALERT_RULES
alert_level=WARN
alert_message=test quiet-hours config validation
generated_at_utc=2026-03-12T13:18:39Z
rule.unresolved_challenges.value=1
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.value=0.00
EOF

echo "[TEST] pr7 should fail closed on invalid quiet-hours config"

set +e
python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$REPORT" \
  --channel slack \
  --audit-file "$TMP/audit.jsonl" \
  --state-file "$TMP/state.json" \
  --dead-letter-file "$TMP/dead-letter.jsonl" \
  --min-level WARN \
  --quiet-hours-enabled \
  --quiet-hours-start 25:00 \
  --quiet-hours-end 08:00 \
  --quiet-hours-tz UTC \
  --dry-run >"$TMP/bad-hhmm.out" 2>&1
rc_bad_hhmm=$?

python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$REPORT" \
  --channel slack \
  --audit-file "$TMP/audit.jsonl" \
  --state-file "$TMP/state.json" \
  --dead-letter-file "$TMP/dead-letter.jsonl" \
  --min-level WARN \
  --quiet-hours-enabled \
  --quiet-hours-start 23:00 \
  --quiet-hours-end 08:00 \
  --quiet-hours-tz Mars/Olympus \
  --dry-run >"$TMP/bad-tz.out" 2>&1
rc_bad_tz=$?
set -e

if [[ "$rc_bad_hhmm" -eq 0 ]]; then
  echo "[FAIL] expected invalid quiet-hours HH:MM to fail"
  cat "$TMP/bad-hhmm.out"
  exit 1
fi

if [[ "$rc_bad_tz" -eq 0 ]]; then
  echo "[FAIL] expected invalid quiet-hours timezone to fail"
  cat "$TMP/bad-tz.out"
  exit 1
fi

grep -q 'invalid quiet-hours config: invalid HH:MM value: 25:00' "$TMP/bad-hhmm.out"
grep -q 'invalid quiet-hours config:' "$TMP/bad-tz.out"
grep -q 'Mars/Olympus' "$TMP/bad-tz.out"

echo "[OK] pr7 rejects invalid quiet-hours time and timezone configuration"
