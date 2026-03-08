#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/web4-release-aggregate-duplicate-required-gate.log"

if WEB4_RELEASE_REQUIRED_GATES="scripts/v2/e3_enterprise_runbook_required_sections_test.sh,scripts/v2/e3_enterprise_runbook_required_sections_test.sh" \
  WEB4_RELEASE_RUN_DIR="$TMP_DIR/run" \
  WEB4_RELEASE_RUN_STAMP="20260308-000000" \
  "$ROOT/scripts/v2/web4_release_aggregate_gate.sh" >"$LOG" 2>&1; then
  echo "[FAIL] expected duplicate required gate to be rejected" >&2
  exit 1
fi

grep -q "duplicate required gate detected" "$LOG"

echo "[WEB4-RELEASE][PASS] duplicate required gate is rejected"
