#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-threshold-diff.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 6,
    "alerts_suppressed": 2,
    "alerts_failed": 1
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr9/alert-thresholds.previous.env" <<'ENV'
WARN_UNRESOLVED_CHALLENGES=2
FAIL_UNRESOLVED_CHALLENGES=5
ENV

cat >"$TMP/run/pr9/alert-thresholds.env" <<'ENV'
WARN_UNRESOLVED_CHALLENGES=3
FAIL_UNRESOLVED_CHALLENGES=5
WARN_FORFEITS_DAILY_INCREASE=4
ENV

cat >"$TMP/run/pr9/history/weekly-alert-governance-20260305T000000Z.json" <<'JSON'
{
  "metrics": {
    "alerts_total": 8,
    "suppression_rate_pct": 12.5,
    "failure_rate_pct": 12.5,
    "delivery_success_rate_pct": 75.0,
    "suppression_share_pct": 12.5
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": [
      {"key": "WARN_UNRESOLVED_CHALLENGES", "old": "2", "new": "4"},
      {"key": "WARN_ESCROW_NONZERO_HOURS", "old": "12", "new": "10"}
    ]
  },
  "history_fingerprint_sha256": "prev-threshold-diff"
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
changed = payload['threshold']['changed_keys']

assert [item['key'] for item in changed] == [
    'WARN_FORFEITS_DAILY_INCREASE',
    'WARN_UNRESOLVED_CHALLENGES',
], changed
assert wow['available'] is True, wow
assert wow['threshold_changed_keys_delta'] == 0, wow
assert wow['threshold_new_keys_vs_last_week'] == ['WARN_FORFEITS_DAILY_INCREASE'], wow
assert wow['threshold_removed_keys_vs_last_week'] == ['WARN_ESCROW_NONZERO_HOURS'], wow
print('[OK] pr9 weekly alert governance reports threshold key churn vs previous weekly baseline')
PY
