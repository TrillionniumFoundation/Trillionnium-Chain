#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-future-history-baseline.XXXXXX")"
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
    "alerts_total": 9,
    "suppression_rate_pct": 20.0,
    "failure_rate_pct": 5.0,
    "delivery_success_rate_pct": 80.0,
    "suppression_share_pct": 20.0
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": []
  },
  "history_fingerprint_sha256": "past"
}
JSON

cat >"$TMP/run/pr9/history/weekly-alert-governance-29990101T000000Z.json" <<'JSON'
{
  "metrics": {
    "alerts_total": 999,
    "suppression_rate_pct": 99.0,
    "failure_rate_pct": 99.0,
    "delivery_success_rate_pct": 1.0,
    "suppression_share_pct": 99.0
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": []
  },
  "history_fingerprint_sha256": "future"
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
assert wow['alerts_total_delta'] == -4, wow
assert wow['delivery_success_rate_pct_delta'] == 20.0, wow
print('[OK] pr9 weekly alert governance ignores future-dated history snapshots when selecting the weekly baseline')
PY
