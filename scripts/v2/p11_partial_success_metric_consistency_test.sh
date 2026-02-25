#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

STATE="$TMP_DIR/state.json"
DEAD="$TMP_DIR/dead.jsonl"
AUDIT="$TMP_DIR/audit.jsonl"
OUT="$TMP_DIR/out.txt"
JSON_OUT="$TMP_DIR/out.json"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

: >"$DEAD"

cat >"$STATE" <<'JSON'
{
  "stats": {
    "alerts_sent": 1,
    "alerts_failed": 0,
    "alerts_suppressed": 0
  },
  "last_delivery": {
    "event": "partial_success",
    "reason": "partial_success:slack",
    "channel": "imessage"
  }
}
JSON

# Legacy per-channel rows include one failed channel + one successful channel,
# while delivery_summary marks overall event as success (partial_success).
cat >"$AUDIT" <<JSON
{"at_utc":"$NOW","channel":"slack","ok":false,"attempts":3}
{"at_utc":"$NOW","channel":"imessage","ok":true,"attempts":1}
{"at_utc":"$NOW","record_type":"delivery_summary","event":"partial_success","ok":true,"attempts":4,"channels_total":2,"channels_ok":1,"channels_failed":1}
JSON

"$ROOT/scripts/v2/p11_policy_rollback_guard.py" \
  --state-file "$STATE" \
  --dead-letter-file "$DEAD" \
  --audit-file "$AUDIT" \
  --lookback-seconds 3600 \
  --failed-rate-threshold-pct 20 \
  --consecutive-failures-threshold 10 \
  --out "$OUT" \
  --json-out "$JSON_OUT" >/dev/null

if ! grep -q '^status=PASS$' "$OUT"; then
  echo "[TEST][FAIL] expected PASS when delivery_summary marks partial_success as overall success"
  cat "$OUT"
  exit 1
fi
if ! grep -q '^failed_rate_basis=audit_window$' "$OUT"; then
  echo "[TEST][FAIL] expected audit_window basis"
  cat "$OUT"
  exit 1
fi
if ! grep -q '^samples_total=1$' "$OUT"; then
  echo "[TEST][FAIL] expected summary-level samples_total=1 (not per-channel)"
  cat "$OUT"
  exit 1
fi

echo "[TEST][PASS] p11/pr7 partial_success metric consistency covered"
