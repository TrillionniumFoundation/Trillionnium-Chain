#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-p11-invalid-attempts-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

STATE="$TMP/state.json"
DEAD="$TMP/dead-letter.jsonl"
AUDIT="$TMP/audit.jsonl"
OUT="$TMP/out.txt"
JSON="$TMP/out.json"

cat > "$STATE" <<'JSON'
{"stats":{"alerts_sent":1,"alerts_failed":0,"alerts_suppressed":0}}
JSON
: > "$DEAD"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "$AUDIT" <<JSONL
{"at_utc":"$TS","ok":false,"attempts":"NaN"}
{"at_utc":"$TS","ok":true,"attempts":1}
JSONL

python3 ./scripts/v2/p11_policy_rollback_guard.py \
  --state-file "$STATE" \
  --dead-letter-file "$DEAD" \
  --audit-file "$AUDIT" \
  --lookback-seconds 3600 \
  --failed-rate-threshold-pct 20 \
  --consecutive-failures-threshold 10 \
  --out "$OUT" \
  --json-out "$JSON" >/dev/null

grep -q '^status=PASS$' "$OUT"
grep -q '^samples_total=1$' "$OUT"
grep -q '^samples_failed=0$' "$OUT"
grep -q '^failed_rate_pct=0.00$' "$OUT"

echo "[OK] p11 rollback guard tolerates malformed attempts fields without false rollback"
