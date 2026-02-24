#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REPORT="$TMP_DIR/summary.txt"
STATE="$TMP_DIR/state.json"
AUDIT="$TMP_DIR/audit.jsonl"

cat >"$REPORT" <<'EOF'
status=WARN
alert_level=CRITICAL
alert_code=PR6_ALERT_RULES
alert_message=inconsistent level payload
generated_at_utc=2026-02-24T00:00:00Z
rule.unresolved_challenges.status=WARN
rule.forfeits_daily_increase.status=PASS
rule.escrow_nonzero_hours.status=PASS
rule.unresolved_challenges.value=1
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.value=0
EOF

echo "[TEST] pr7 should reject inconsistent status/alert_level and must not bypass quiet-hours"
OUT="$TMP_DIR/out.txt"
python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$REPORT" \
  --state-file "$STATE" \
  --dead-letter-file "$TMP_DIR/dead-letter.jsonl" \
  --audit-file "$AUDIT" \
  --channel imessage \
  --min-level WARN \
  --quiet-hours-enabled \
  --quiet-hours-start 00:00 \
  --quiet-hours-end 23:59 \
  --quiet-hours-tz UTC \
  --dry-run \
  >"$OUT"

grep -q "suppressed(consistency): inconsistent_status_alert_level" "$OUT"
grep -q '"rejected": true' "$AUDIT"
grep -q '"reason": "inconsistent_status_alert_level: status=WARN=>WARN, alert_level=CRITICAL"' "$AUDIT"

echo "[OK] pr7 rejects inconsistent status/alert_level and blocks quiet-hours bypass"
