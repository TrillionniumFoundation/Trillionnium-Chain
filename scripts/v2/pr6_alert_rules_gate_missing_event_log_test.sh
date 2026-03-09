#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr6-gate-missing-log-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MISSING_LOG="$TMP/not-found.log"

set +e
EVENT_LOG="$MISSING_LOG" RUN_DIR="$TMP/run" \
  "$ROOT/scripts/v2/pr6_alert_rules_gate.sh" >"$TMP/out.log" 2>&1
rc=$?
set -e

if [[ $rc -ne 3 ]]; then
  echo "[FAIL] expected rc=3 for missing event log, got rc=$rc"
  cat "$TMP/out.log"
  exit 1
fi

if ! grep -q "\[PR6\]\[FAIL\] rc=3 event log not found" "$TMP/out.log"; then
  echo "[FAIL] expected observability message for missing event log"
  cat "$TMP/out.log"
  exit 1
fi

echo "[OK] pr6 gate reports rc=3 when event log is missing"
