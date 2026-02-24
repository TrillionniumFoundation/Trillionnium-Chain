#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-p11-rejected-attempts0-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

STATE="$TMP/state.json"
DEAD="$TMP/dead-letter.jsonl"
AUDIT="$TMP/audit.jsonl"
OUT="$TMP/out.txt"
JSON="$TMP/out.json"

cat > "$STATE" <<'EOF'
{"stats":{"alerts_sent":1,"alerts_failed":0,"alerts_suppressed":0}}
EOF
: > "$DEAD"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "$AUDIT" <<JSONL
{"at_utc":"$TS","ok":false,"attempts":0,"rejected":true,"reason":"inconsistent_status_alert_level"}
{"at_utc":"$TS","ok":true,"attempts":1,"rejected":false}
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
grep -q '^failed_rate_basis=audit_window$' "$OUT"
grep -q '^samples_total=1$' "$OUT"
grep -q '^samples_failed=0$' "$OUT"
grep -q '^failed_rate_pct=0.00$' "$OUT"

echo "[OK] p11 rollback guard excludes rejected/attempts=0 from delivery failure samples"
