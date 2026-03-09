#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/web4-release-aggregate-empty-override.log"

if WEB4_RELEASE_REQUIRED_GATES=" ,  , " \
  WEB4_RELEASE_RUN_DIR="$TMP_DIR/run" \
  "$ROOT/scripts/v2/web4_release_aggregate_gate.sh" >"$LOG" 2>&1; then
  echo "[FAIL] expected empty override list to be rejected" >&2
  exit 1
fi

grep -q "required gate list is empty" "$LOG"

echo "[WEB4-RELEASE][PASS] empty WEB4_RELEASE_REQUIRED_GATES override is rejected"
