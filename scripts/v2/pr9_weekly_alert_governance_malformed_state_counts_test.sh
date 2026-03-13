#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-malformed-state.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": "abc",
    "alerts_suppressed": null,
    "alerts_failed": "1.5"
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"partial_success","channels_ok":1,"channels_failed":1}
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

assert metrics['alerts_sent'] == 0, metrics
assert metrics['alerts_suppressed'] == 0, metrics
assert metrics['alerts_failed'] == 0, metrics
assert metrics['alerts_total'] == 0, metrics
assert metrics['delivery_attempted'] == 0, metrics
assert metrics['delivery_success_rate_pct'] is None, metrics
assert metrics['suppression_rate_pct'] == 0.0, metrics
assert metrics['failure_rate_pct'] == 0.0, metrics
assert metrics['suppression_share_pct'] == 0.0, metrics
assert metrics['delivery_summary_count'] == 1, metrics
assert metrics['partial_success_count'] == 1, metrics
assert metrics['channel_delivery_success_rate_pct'] == 50.0, metrics
print('[OK] pr9 weekly alert governance clamps malformed state counters to safe zeros without corrupting audit-derived delivery metrics')
PY
