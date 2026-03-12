#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-export-env.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 5,
    "alerts_suppressed": 1,
    "alerts_failed": 0
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr9/alert-thresholds.previous.env" <<'ENV'
export WARN_UNRESOLVED_CHALLENGES=2
export FAIL_UNRESOLVED_CHALLENGES=5
ENV

cat >"$TMP/run/pr9/alert-thresholds.env" <<'ENV'
export WARN_UNRESOLVED_CHALLENGES=4
export FAIL_UNRESOLVED_CHALLENGES=5
ENV

cat >"$TMP/run/pr9/history/weekly-alert-governance-20260305T000000Z.json" <<'JSON'
{
  "metrics": {
    "alerts_total": 4,
    "suppression_rate_pct": 25.0,
    "failure_rate_pct": 0.0,
    "delivery_success_rate_pct": 100.0,
    "suppression_share_pct": 25.0
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": []
  },
  "history_fingerprint_sha256": "prev-export-env"
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
changed = payload['threshold']['changed_keys']
wow = payload['week_over_week']

assert [item['key'] for item in changed] == ['WARN_UNRESOLVED_CHALLENGES'], changed
assert changed[0]['old'] == '2', changed
assert changed[0]['new'] == '4', changed
assert wow['threshold_changed_keys_delta'] == 1, wow
assert wow['threshold_new_keys_vs_last_week'] == ['WARN_UNRESOLVED_CHALLENGES'], wow
print('[OK] pr9 weekly alert governance parses shell-style export KEY=value threshold env files')
PY
