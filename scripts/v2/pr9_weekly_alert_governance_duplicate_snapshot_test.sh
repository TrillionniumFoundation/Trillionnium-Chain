#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-dup-snapshot.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 2,
    "alerts_suppressed": 1,
    "alerts_failed": 0
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr7-alert-delivery/dead-letter.jsonl" <<'JSONL'
{"created_at_utc":"2026-03-11T12:00:00Z","message":"recent"}
JSONL

pushd "$TMP" >/dev/null
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >"$TMP/first.out"
first_count=$(find "$TMP/run/pr9/history" -name 'weekly-alert-governance-*.json' | wc -l | tr -d ' ')

sleep 1

python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >"$TMP/second.out"
second_count=$(find "$TMP/run/pr9/history" -name 'weekly-alert-governance-*.json' | wc -l | tr -d ' ')

sleep 1

python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >"$TMP/third.out"
third_count=$(find "$TMP/run/pr9/history" -name 'weekly-alert-governance-*.json' | wc -l | tr -d ' ')
popd >/dev/null

if [[ "$first_count" != "1" ]]; then
  echo "[FAIL] expected first run to create exactly one history snapshot, got $first_count"
  exit 1
fi

if [[ "$second_count" != "2" ]]; then
  echo "[FAIL] expected second run to create a new history snapshot once baseline data becomes available, got $second_count"
  exit 1
fi

if [[ "$third_count" != "2" ]]; then
  echo "[FAIL] expected stable third run to skip duplicate history snapshot, got $third_count"
  exit 1
fi

grep -q "skipped duplicate history snapshot" "$TMP/third.out"

echo "[OK] pr9 weekly alert governance skips duplicate history snapshots after baseline state stabilizes"
