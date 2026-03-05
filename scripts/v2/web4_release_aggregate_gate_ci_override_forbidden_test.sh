#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/web4-release-aggregate-ci-override-forbidden.log"

if CI=true WEB4_RELEASE_REQUIRED_GATES="scripts/v2/e3_enterprise_runbook_required_sections_test.sh" \
  WEB4_RELEASE_RUN_DIR="$TMP_DIR/run" \
  "$ROOT/scripts/v2/web4_release_aggregate_gate.sh" >"$LOG" 2>&1; then
  echo "[FAIL] expected CI override to be rejected" >&2
  exit 1
fi

grep -q "override is forbidden in CI" "$LOG"

echo "[WEB4-RELEASE][PASS] CI override guard rejects WEB4_RELEASE_REQUIRED_GATES"
