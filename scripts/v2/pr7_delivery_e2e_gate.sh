#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REPORT="$TMP_DIR/pr6-summary-warn.txt"
cat >"$REPORT" <<'EOF'
status=WARN
alert_code=PR6_ALERT_RULES
alert_message=e2e gate simulated warning
generated_at_utc=2026-02-24T00:00:00+00:00
rule.unresolved_challenges.status=WARN
rule.unresolved_challenges.value=4
rule.forfeits_daily_increase.status=WARN
rule.forfeits_daily_increase.value=72
rule.escrow_nonzero_hours.status=WARN
rule.escrow_nonzero_hours.value=17.20
EOF

DLQ="$TMP_DIR/dead-letter.jsonl"
python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$REPORT" \
  --channel imessage \
  --state-file "$TMP_DIR/state.json" \
  --dead-letter-file "$DLQ" \
  --audit-file "$TMP_DIR/audit.jsonl" \
  --dry-run \
  --dry-run-fail-channels imessage \
  --dry-run-simulate-failures 9 \
  --max-retries 2 \
  --base-backoff-ms 5 \
  --max-backoff-ms 10 >/dev/null || true

if [[ ! -s "$DLQ" ]]; then
  echo "[PR7][E2E][FAIL] expected dead-letter produced in failure phase" >&2
  exit 1
fi

python3 "$ROOT/scripts/v2/pr7_dead_letter_replay.py" \
  --dead-letter-file "$DLQ" \
  --receipt-file "$TMP_DIR/replayed.jsonl" \
  --lock-file "$TMP_DIR/replay.lock" \
  --dry-run \
  --max-retries 1 \
  --base-backoff-ms 5 \
  --max-backoff-ms 10 >/dev/null

if [[ -s "$DLQ" ]]; then
  echo "[PR7][E2E][FAIL] expected dead-letter drained after replay" >&2
  cat "$DLQ" >&2
  exit 1
fi

echo "[PR7][E2E][PASS] delivery failure->dead-letter->replay loop reachable"