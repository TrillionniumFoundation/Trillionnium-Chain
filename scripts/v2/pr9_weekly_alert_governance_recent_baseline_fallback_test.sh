#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-recent-baseline-fallback.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

snapshot_name="$(python3 - <<'PY'
import datetime as dt
now = dt.datetime.now(dt.timezone.utc)
ts = (now - dt.timedelta(days=2)).strftime('%Y%m%dT%H%M%SZ')
print(f'weekly-alert-governance-{ts}.json')
PY
)"

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
{"at_utc":"2026-03-12T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr9/history/$snapshot_name" <<'JSON'
{
  "metrics": {
    "alerts_total": 1,
    "suppression_rate_pct": 0,
    "failure_rate_pct": 0,
    "delivery_success_rate_pct": 100,
    "suppression_share_pct": 0
  },
  "topn": {
    "unresolved": [],
    "forfeit": [],
    "escrow": []
  },
  "threshold": {
    "changed_keys": []
  },
  "history_fingerprint_sha256": "recent-only-baseline"
}
JSON

pushd "$TMP" >/dev/null
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >/dev/null
popd >/dev/null

python3 - "$TMP/run/pr9/out.json" "$snapshot_name" <<'PY'
import json
import math
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
expected_name = sys.argv[2]
wow = payload['week_over_week']

assert wow['available'] is True, wow
assert wow['baseline_json'].endswith(expected_name), wow
assert wow['alerts_total_delta'] == 2, wow
assert math.isclose(wow['suppression_rate_pct_delta'], 33.33333333333333, rel_tol=0, abs_tol=1e-9), wow
assert wow['failure_rate_pct_delta'] == 0.0, wow
assert wow['delivery_success_rate_pct_delta'] == 0.0, wow
assert math.isclose(wow['suppression_share_pct_delta'], 33.33333333333333, rel_tol=0, abs_tol=1e-9), wow
print('[OK] pr9 weekly alert governance falls back to a recent snapshot when no mature weekly baseline exists yet')
PY
