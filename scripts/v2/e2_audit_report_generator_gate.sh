#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT_DIR="$ROOT/scripts/v2"

mapfile -t TESTS < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name 'e2_audit_report_generator_*_test.sh' | sort)

if [[ ${#TESTS[@]} -eq 0 ]]; then
  echo "[FAIL] no E2 audit report generator tests found" >&2
  exit 1
fi

for t in "${TESTS[@]}"; do
  bash "$t"
done

echo "[PASS] e2_audit_report_generator_gate (${#TESTS[@]} tests)"
