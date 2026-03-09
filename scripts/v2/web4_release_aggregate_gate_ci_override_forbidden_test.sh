#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

for ci_value in true TRUE 1 yes; do
  LOG="$TMP_DIR/web4-release-aggregate-ci-override-forbidden-${ci_value}.log"

  if CI="$ci_value" WEB4_RELEASE_REQUIRED_GATES="scripts/v2/e3_enterprise_runbook_required_sections_test.sh" \
    WEB4_RELEASE_RUN_DIR="$TMP_DIR/run-$ci_value" \
    "$ROOT/scripts/v2/web4_release_aggregate_gate.sh" >"$LOG" 2>&1; then
    echo "[FAIL] expected CI override to be rejected when CI=$ci_value" >&2
    exit 1
  fi

  grep -q "override is forbidden in CI" "$LOG"
done

ALLOW_LOG="$TMP_DIR/web4-release-aggregate-ci-override-allowed.log"
CI=true WEB4_RELEASE_ALLOW_CI_OVERRIDE=1 \
  WEB4_RELEASE_REQUIRED_GATES="scripts/v2/e3_enterprise_runbook_required_sections_test.sh" \
  WEB4_RELEASE_RUN_STAMP="20260309-000000" \
  WEB4_RELEASE_RUN_DIR="$TMP_DIR/run-allow" \
  "$ROOT/scripts/v2/web4_release_aggregate_gate.sh" >"$ALLOW_LOG" 2>&1

grep -q "\[WEB4-RELEASE\]\[PASS\] all required Web4 high-risk gates passed" "$ALLOW_LOG"

echo "[WEB4-RELEASE][PASS] CI override guard rejects truthy CI variants by default and allows explicit debug override"
