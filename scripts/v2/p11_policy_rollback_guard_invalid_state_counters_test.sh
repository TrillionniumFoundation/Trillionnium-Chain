#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-p11-invalid-state-counters-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

STATE="$TMP/state.json"
DEAD="$TMP/dead-letter.jsonl"
AUDIT="$TMP/audit.jsonl"
OUT="$TMP/out.txt"
JSON="$TMP/out.json"

cat > "$STATE" <<'JSON'
{"stats":{"alerts_sent":"NaN","alerts_failed":-7,"alerts_suppressed":""}}
JSON
: > "$DEAD"
: > "$AUDIT"

python3 ./scripts/v2/p11_policy_rollback_guard.py \
  --state-file "$STATE" \
  --dead-letter-file "$DEAD" \
  --audit-file "$AUDIT" \
  --lookback-seconds 3600 \
  --failed-rate-threshold-pct 20 \
  --consecutive-failures-threshold 10 \
  --out "$OUT" \
  --json-out "$JSON" >/dev/null

grep -q '^status=WARN$' "$OUT"
grep -q '^samples_state_sent=0$' "$OUT"
grep -q '^samples_state_failed=0$' "$OUT"
grep -q '^samples_state_suppressed=0$' "$OUT"

echo "[OK] p11 rollback guard tolerates malformed state counters without crashing"
