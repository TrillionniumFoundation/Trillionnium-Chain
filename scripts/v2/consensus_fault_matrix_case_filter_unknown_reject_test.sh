#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh"

set +e
output="$(CASE_FILTER='unknown_case' "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for unknown CASE_FILTER token" >&2
  exit 1
fi

if ! grep -Fq "unknown case 'unknown_case'" <<<"$output"; then
  echo "[FAIL] missing explicit unknown-case error in output" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] consensus fault matrix rejects unknown CASE_FILTER tokens"
