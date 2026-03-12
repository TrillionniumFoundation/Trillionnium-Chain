#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-lookback.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 9,
    "alerts_suppressed": 2,
    "alerts_failed": 1
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
{"at_utc":"2026-03-01T00:00:00Z","record_type":"delivery_summary","event":"partial_success","channels_ok":1,"channels_failed":1}
JSONL

cat >"$TMP/run/pr7-alert-delivery/dead-letter.jsonl" <<'JSONL'
{"created_at_utc":"2026-03-11T12:00:00Z","message":"recent"}
{"created_at_utc":"2026-03-01T12:00:00Z","message":"old"}
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

assert metrics['delivery_summary_count'] == 1, metrics
assert metrics['partial_success_count'] == 0, metrics
assert metrics['channels_ok_total'] == 1, metrics
assert metrics['channels_failed_total'] == 0, metrics
assert metrics['channel_delivery_success_rate_pct'] == 100.0, metrics
assert metrics['dead_letter_entries'] == 1, metrics
print('[OK] pr9 weekly alert governance lookback window filters audit/dead-letter metrics consistently')
PY
