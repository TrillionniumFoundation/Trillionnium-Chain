#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-zero-threshold-churn.XXXXXX")"
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
WARN_UNRESOLVED_CHALLENGES=2
FAIL_UNRESOLVED_CHALLENGES=5
ENV

cat >"$TMP/run/pr9/alert-thresholds.env" <<'ENV'
WARN_UNRESOLVED_CHALLENGES=2
FAIL_UNRESOLVED_CHALLENGES=5
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
  "history_fingerprint_sha256": "prev-zero-threshold-churn"
}
JSON

pushd "$TMP" >/dev/null
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >/dev/null
popd >/dev/null

python3 - "$TMP/run/pr9/out.md" <<'PY'
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding='utf-8')
needle = """### changed keys vs last week
- newly_changed_keys: `0`
  - none
- no_longer_changed_keys: `0`
  - none
"""
assert needle in text, text
print('[OK] pr9 weekly alert governance renders explicit none markers for zero threshold churn markdown sections')
PY
