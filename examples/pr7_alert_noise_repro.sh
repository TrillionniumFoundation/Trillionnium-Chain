#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="${TMP_DIR:-/tmp/pr7-alert-noise-repro}"
STATE="$TMP_DIR/state.json"
WARN_REPORT="$TMP_DIR/warn-summary.txt"
CRIT_REPORT="$TMP_DIR/critical-summary.txt"

mkdir -p "$TMP_DIR"
rm -f "$STATE"

cat > "$WARN_REPORT" <<'EOF'
status=WARN
alert_code=PR6_ALERT_RULES
alert_message=warn test event
generated_at_utc=2026-02-23T10:00:00+00:00
rule.unresolved_challenges.status=WARN
rule.unresolved_challenges.value=4
rule.forfeits_daily_increase.status=WARN
rule.forfeits_daily_increase.value=72
rule.escrow_nonzero_hours.status=PASS
rule.escrow_nonzero_hours.value=0
EOF

cat > "$CRIT_REPORT" <<'EOF'
status=FAIL
alert_code=PR6_ALERT_RULES
alert_message=critical test event
generated_at_utc=2026-02-23T10:00:00+00:00
rule.unresolved_challenges.status=FAIL
rule.unresolved_challenges.value=11
rule.forfeits_daily_increase.status=PASS
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.status=FAIL
rule.escrow_nonzero_hours.value=23.5
EOF

echo "[repro] case1 WARN first send"
DRY_RUN=1 python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$WARN_REPORT" \
  --channel imessage \
  --state-file "$STATE" \
  --min-level WARN \
  --dedup-seconds 60

echo "[repro] case2 WARN duplicate in cooldown -> suppressed"
DRY_RUN=1 python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$WARN_REPORT" \
  --channel imessage \
  --state-file "$STATE" \
  --min-level WARN \
  --dedup-seconds 60

echo "[repro] case3 CRITICAL first send"
DRY_RUN=1 python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$CRIT_REPORT" \
  --channel imessage \
  --state-file "$STATE" \
  --min-level WARN \
  --dedup-seconds 60

echo "[repro] case4 CRITICAL duplicate in cooldown -> still exact dedup suppressed"
DRY_RUN=1 python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$CRIT_REPORT" \
  --channel imessage \
  --state-file "$STATE" \
  --min-level WARN \
  --dedup-seconds 60

echo "[repro] done"