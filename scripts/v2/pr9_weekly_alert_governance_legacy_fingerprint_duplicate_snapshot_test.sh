#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-legacy-dup-snapshot.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alert-delivery" "$TMP/run/pr9/history"

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
{"at_utc":"2026-03-11T00:00:00Z","record_type":"delivery_summary","event":"sent","channels_ok":1,"channels_failed":0}
JSONL

cat >"$TMP/run/pr7-alert-delivery/dead-letter.jsonl" <<'JSONL'
{"created_at_utc":"2026-03-11T12:00:00Z","message":"recent"}
JSONL

pushd "$TMP" >/dev/null
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >"$TMP/first.out"

sleep 1

python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >"$TMP/second-bootstrap.out"

legacy_snapshot="$(find "$TMP/run/pr9/history" -name 'weekly-alert-governance-*.json' | sort | tail -n1)"
python3 - "$legacy_snapshot" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding='utf-8'))
payload.pop('history_fingerprint_sha256', None)
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
PY

sleep 1

python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" \
  --lookback-days 7 \
  --json-out run/pr9/out.json \
  --out run/pr9/out.md >"$TMP/third.out"
count=$(find "$TMP/run/pr9/history" -name 'weekly-alert-governance-*.json' | wc -l | tr -d ' ')
popd >/dev/null

if [[ "$count" != "2" ]]; then
  echo "[FAIL] expected legacy snapshot without embedded fingerprint to suppress duplicate history snapshot after baseline stabilized, got $count"
  find "$TMP/run/pr9/history" -name 'weekly-alert-governance-*.json' | sort
  exit 1
fi

grep -q "skipped duplicate history snapshot" "$TMP/third.out"

echo "[OK] pr9 duplicate snapshot suppression handles legacy snapshots without embedded fingerprints"
