#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Explicit, bounded list of the gate-level contracts restored with the hardened
# PR7 driver. Keep operational commands and open-ended discovery out of this
# suite so it remains safe for a quick CI lane.
TESTS=(
  "scripts/v2/pr7_alert_delivery_gate_empty_delivery_cmd_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_invalid_audit_utf8_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_invalid_fail_mode_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_invalid_lock_config_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_invalid_min_level_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_lock_timeout_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_malformed_quoted_cmd_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_min_level_alias_route_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_missing_summary_fallback_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_quoted_cmd_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_route_retry_collapse_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_skip_min_level_status_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_status_summary_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_zero_argv_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_concurrency_guard_test.sh"
  "scripts/v2/pr7_alert_delivery_gate_rc_observability_test.sh"
)

passed=0
for relative_test in "${TESTS[@]}"; do
  test_path="$ROOT/$relative_test"
  if [[ ! -x "$test_path" ]]; then
    echo "[PR7][REGRESSION][FAIL] test missing or not executable: $relative_test" >&2
    exit 2
  fi
  echo "[PR7][REGRESSION] run=$relative_test"
  "$test_path"
  passed=$((passed + 1))
done

echo "[PR7][REGRESSION][PASS] tests=$passed"
