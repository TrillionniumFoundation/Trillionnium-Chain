#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-non-finite-channels.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 1,
    "alerts_suppressed": 0,
    "alerts_failed": 0
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"partial_success","channels_ok":NaN,"channels_failed":Infinity}
{"at_utc":"2026-03-11T00:30:00Z","record_type":"delivery_summary","event":"sent","channels_ok":"3","channels_failed":"-Infinity"}
JSONL

pushd "$TMP" >/dev/null
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >/dev/null
popd >/dev/null

python3 - "$TMP/run/pr9/out.json" <<'PY'
import json
import math
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
metrics = payload['metrics']

assert metrics['delivery_summary_count'] == 2, metrics
assert metrics['partial_success_count'] == 1, metrics
assert metrics['channels_ok_total'] == 3, metrics
assert metrics['channels_failed_total'] == 0, metrics
assert math.isclose(metrics['channel_delivery_success_rate_pct'], 100.0, rel_tol=0, abs_tol=1e-9), metrics
print('[OK] pr9 weekly alert governance clamps non-finite audit channel counters to zero')
PY
