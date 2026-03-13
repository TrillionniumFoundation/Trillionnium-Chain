#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-non-object-rows.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 4,
    "alerts_suppressed": 1,
    "alerts_failed": 0
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":2,"channels_failed":0}
[1,2,3]
"noise"
123
{"at_utc":"2026-03-11T01:00:00Z","record_type":"delivery_summary","event":"partial_success","channels_ok":1,"channels_failed":1}
JSONL

cat >"$TMP/run/pr7-alert-delivery/dead-letter.jsonl" <<'JSONL'
{"created_at_utc":"2026-03-11T12:00:00Z","message":"recent"}
["bad"]
"noise"
42
{"created_at_utc":"2026-03-11T13:00:00Z","message":"recent-2"}
JSONL

pushd "$TMP" >/dev/null
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >/dev/null
popd >/dev/null

python3 - "$TMP/run/pr9/out.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
metrics = payload['metrics']

assert metrics['delivery_summary_count'] == 2, metrics
assert metrics['partial_success_count'] == 1, metrics
assert metrics['channels_ok_total'] == 3, metrics
assert metrics['channels_failed_total'] == 1, metrics
assert metrics['channel_delivery_success_rate_pct'] == 75.0, metrics
assert metrics['dead_letter_entries'] == 2, metrics
print('[OK] pr9 weekly alert governance ignores malformed non-object JSONL rows in audit/dead-letter inputs')
PY
