#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-single-quote-hash-comment-env.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

cat >"$TMP/run/pr7-alert-delivery/state.json" <<'JSON'
{
  "stats": {
    "alerts_sent": 2,
    "alerts_suppressed": 0,
    "alerts_failed": 0
  }
}
JSON

cat >"$TMP/run/pr7-alert-delivery/audit.jsonl" <<'JSONL'
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr9/alert-thresholds.previous.env" <<'ENV'
export ALERT_NOTIFY_CHANNEL_WARN='slack #ops primary' # previous routed label
ENV

cat >"$TMP/run/pr9/alert-thresholds.env" <<'ENV'
export ALERT_NOTIFY_CHANNEL_WARN='slack #ops backup' # current routed label
ENV

cat >"$TMP/run/pr9/history/weekly-alert-governance-20260305T000000Z.json" <<'JSON'
{
  "metrics": {
    "alerts_total": 1,
    "suppression_rate_pct": 0.0,
    "failure_rate_pct": 0.0,
    "delivery_success_rate_pct": 100.0,
    "suppression_share_pct": 0.0
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": []
  },
  "history_fingerprint_sha256": "prev-single-quote-hash-comment-thresholds"
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
assert changed == [{
    'key': 'ALERT_NOTIFY_CHANNEL_WARN',
    'old': 'slack #ops primary',
    'new': 'slack #ops backup',
}], changed
assert payload['week_over_week']['threshold_changed_keys_delta'] == 1, payload['week_over_week']
print('[OK] pr9 weekly alert governance preserves literal hashes in single-quoted values with trailing inline comments')
PY
