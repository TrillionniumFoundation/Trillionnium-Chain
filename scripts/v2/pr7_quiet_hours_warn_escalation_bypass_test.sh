#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REPORT="$TMP_DIR/summary.txt"
STATE="$TMP_DIR/state.json"

cat >"$REPORT" <<'EOF'
status=WARN
alert_level=WARN
alert_code=PR6_ALERT_RULES
alert_message=warn signal
generated_at_utc=2026-02-24T00:00:00Z
rule.unresolved_challenges.status=WARN
rule.forfeits_daily_increase.status=PASS
rule.escrow_nonzero_hours.status=PASS
rule.unresolved_challenges.value=1
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.value=0
EOF

echo "[TEST] pr7 quiet-hours should suppress WARN even when escalate threshold is reached"
OUT="$TMP_DIR/out.txt"
python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$REPORT" \
  --state-file "$STATE" \
  --dead-letter-file "$TMP_DIR/dead-letter.jsonl" \
  --audit-file "$TMP_DIR/audit.jsonl" \
  --channel imessage \
  --min-level WARN \
  --warn-escalate-count 1 \
  --warn-escalate-window-seconds 3600 \
  --quiet-hours-enabled \
  --quiet-hours-start 00:00 \
  --quiet-hours-end 23:59 \
  --quiet-hours-tz UTC \
  --dry-run \
  >"$OUT"

grep -q "suppressed(quiet-hours): level=WARN" "$OUT"

echo "[OK] pr7 quiet-hours WARN escalation bypass fixed"
