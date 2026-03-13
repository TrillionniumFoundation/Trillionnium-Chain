#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr9-invalid-args.XXXXXX")"
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

pushd "$TMP" >/dev/null
set +e
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" --lookback-days 0 >"$TMP/lookback.out" 2>&1
rc_lookback=$?
python3 "$ROOT/scripts/v2/pr9_weekly_alert_governance.py" --top-n 0 >"$TMP/topn.out" 2>&1
rc_topn=$?
set -e
popd >/dev/null

if [[ "$rc_lookback" -eq 0 ]]; then
  echo "[FAIL] expected --lookback-days 0 to fail"
  cat "$TMP/lookback.out"
  exit 1
fi

if [[ "$rc_topn" -eq 0 ]]; then
  echo "[FAIL] expected --top-n 0 to fail"
  cat "$TMP/topn.out"
  exit 1
fi

grep -q -- '--lookback-days must be >= 1' "$TMP/lookback.out"
grep -q -- '--top-n must be >= 1' "$TMP/topn.out"

echo "[OK] pr9 weekly alert governance rejects non-positive lookback/top-n arguments"
