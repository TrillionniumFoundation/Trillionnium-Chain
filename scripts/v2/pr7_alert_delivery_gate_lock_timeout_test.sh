#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-lock-timeout.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

LOCK_DIR="$TMP/existing-lock"
STATUS_FILE="$TMP/pr7-status.env"
mkdir -p "$LOCK_DIR"
echo 4242 >"$LOCK_DIR/pid"

set +e
RUN_DIR="$TMP/run" \
PR7_STATUS_FILE="$STATUS_FILE" \
PR7_GATE_LOCK_DIR="$LOCK_DIR" \
PR7_GATE_LOCK_WAIT_SECONDS=0 \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/out.log" 2>&1
rc=$?
set -e

if [[ $rc -ne 5 ]]; then
  echo "[FAIL] expected rc=5 for lock timeout, got rc=$rc"
  cat "$TMP/out.log"
  exit 1
fi

if ! grep -q "\[PR7\]\[FAIL\] lock timeout after 0s lock_dir=$LOCK_DIR" "$TMP/out.log"; then
  echo "[FAIL] missing lock timeout stderr detail"
  cat "$TMP/out.log"
  exit 1
fi

if ! grep -q "\[PR7\]\[alert-delivery\] status=LOCK_TIMEOUT pr6_rc=0 pr7_rc=5 final_rc=5" "$TMP/out.log"; then
  echo "[FAIL] missing lock timeout summary line"
  cat "$TMP/out.log"
  exit 1
fi

python3 - "$STATUS_FILE" "$LOCK_DIR" <<'PY'
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
lock_dir = sys.argv[2]
if not status_path.exists():
    raise SystemExit('[FAIL] missing status file for lock timeout path')
rows = {}
for line in status_path.read_text(encoding='utf-8').splitlines():
    if '=' not in line:
        continue
    key, value = line.split('=', 1)
    rows[key] = value
assert rows.get('status') == 'LOCK_TIMEOUT', rows
assert rows.get('pr6_rc') == '0', rows
assert rows.get('pr7_rc') == '5', rows
assert rows.get('final_rc') == '5', rows
assert rows.get('delivery_event') == 'lock_timeout', rows
assert rows.get('lock_dir') == lock_dir, rows
print('[OK] pr7 gate writes lock-timeout observability status before exiting')
PY
