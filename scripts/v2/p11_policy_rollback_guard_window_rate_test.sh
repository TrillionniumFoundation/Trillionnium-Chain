#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-p11-window-rate-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

STATE="$TMP/state.json"
DEAD="$TMP/dead-letter.jsonl"
AUDIT="$TMP/audit.jsonl"
OUT1="$TMP/out-audit.txt"
JSON1="$TMP/out-audit.json"
OUT2="$TMP/out-fallback.txt"
JSON2="$TMP/out-fallback.json"

cat > "$STATE" <<'JSON'
{
  "stats": {
    "alerts_sent": 100000,
    "alerts_failed": 1,
    "alerts_suppressed": 0
  }
}
JSON

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
TS="$(now_utc)"

cat > "$AUDIT" <<JSONL
{"at_utc":"$TS","ok":false}
{"at_utc":"$TS","ok":false}
{"at_utc":"$TS","ok":true}
JSONL

: > "$DEAD"

python3 ./scripts/v2/p11_policy_rollback_guard.py \
  --state-file "$STATE" \
  --dead-letter-file "$DEAD" \
  --audit-file "$AUDIT" \
  --lookback-seconds 3600 \
  --failed-rate-threshold-pct 20 \
  --consecutive-failures-threshold 10 \
  --out "$OUT1" \
  --json-out "$JSON1" >/dev/null

grep -q '^status=FAIL$' "$OUT1"
grep -q '^failed_rate_basis=audit_window$' "$OUT1"
grep -q '^failed_rate_pct=66.67$' "$OUT1"

echo "{\"created_at_utc\":\"$TS\",\"level\":\"ERROR\",\"status\":\"FAIL\",\"message\":\"send failed\"}" > "$DEAD"
rm -f "$AUDIT"

python3 ./scripts/v2/p11_policy_rollback_guard.py \
  --state-file "$STATE" \
  --dead-letter-file "$DEAD" \
  --audit-file "$AUDIT" \
  --lookback-seconds 3600 \
  --failed-rate-threshold-pct 20 \
  --consecutive-failures-threshold 10 \
  --out "$OUT2" \
  --json-out "$JSON2" >/dev/null

grep -q '^status=FAIL$' "$OUT2"
grep -q '^failed_rate_basis=dead_letter_window_fallback$' "$OUT2"
grep -q '^failed_rate_pct=100.00$' "$OUT2"

echo "[OK] p11 rollback guard uses lookback-window failed_rate and resists cumulative dilution"
