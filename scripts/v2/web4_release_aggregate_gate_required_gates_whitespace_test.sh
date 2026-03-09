#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/web4-release-aggregate-whitespace.log"

WEB4_RELEASE_REQUIRED_GATES="  scripts/v2/e3_enterprise_runbook_required_sections_test.sh  " \
WEB4_RELEASE_RUN_DIR="$TMP_DIR/run" \
"$ROOT/scripts/v2/web4_release_aggregate_gate.sh" >"$LOG" 2>&1

grep -q "\[WEB4-RELEASE\] required_gate_count=1" "$LOG"
grep -q "\[WEB4-RELEASE\] required_gate\[00\]=scripts/v2/e3_enterprise_runbook_required_sections_test.sh" "$LOG"
grep -q "\[WEB4-RELEASE\]\[RUN\] scripts/v2/e3_enterprise_runbook_required_sections_test.sh" "$LOG"
grep -q "\[WEB4-RELEASE\]\[PASS\] all required Web4 high-risk gates passed" "$LOG"

echo "[WEB4-RELEASE][PASS] required gate list whitespace handling"
