#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-malformed-prev-metrics.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

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
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr9/history/weekly-alert-governance-20260305T000000Z.json" <<'JSON'
{
  "metrics": {
    "alerts_total": "bad",
    "suppression_rate_pct": "oops",
    "failure_rate_pct": -5,
    "delivery_success_rate_pct": "nan-not-supported",
    "suppression_share_pct": null
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": []
  },
  "history_fingerprint_sha256": "prev-malformed-metrics"
}
JSON

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
wow = payload['week_over_week']

assert wow['available'] is True, wow
assert wow['baseline_json'].endswith('weekly-alert-governance-20260305T000000Z.json'), wow
assert wow['alerts_total_delta'] == 5, wow
assert wow['suppression_rate_pct_delta'] == 20.0, wow
assert wow['failure_rate_pct_delta'] == 0.0, wow
assert wow['delivery_success_rate_pct_delta'] == 100.0, wow
assert wow['suppression_share_pct_delta'] == 20.0, wow
print('[OK] pr9 weekly alert governance clamps malformed previous baseline metrics instead of crashing')
PY
