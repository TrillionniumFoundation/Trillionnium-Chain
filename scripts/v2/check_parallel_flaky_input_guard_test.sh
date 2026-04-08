#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/check_parallel_flaky.sh"

if [[ ! -f "$SCRIPT" ]]; then
  echo "[FAIL] missing script: $SCRIPT" >&2
  exit 1
fi

run_expect_guard_fail() {
  local label="$1"
  shift
  local out
  if out=$("$@" 2>&1); then
    echo "[FAIL] expected validation failure for $label" >&2
    exit 1
  fi
  if [[ "$out" != *"must be a positive integer"* ]]; then
    echo "[FAIL] missing positive integer guard message for $label" >&2
    echo "$out" >&2
    exit 1
  fi
}

run_expect_guard_fail "RUNS=0" env RUNS=0 "$SCRIPT"
run_expect_guard_fail "RUN_TIMEOUT_SEC=0" env RUN_TIMEOUT_SEC=0 "$SCRIPT"
run_expect_guard_fail "RUNS=abc" env RUNS=abc "$SCRIPT"
run_expect_guard_fail "RUN_TIMEOUT_SEC=1.5" env RUN_TIMEOUT_SEC=1.5 "$SCRIPT"

echo "[PASS] check_parallel_flaky rejects non-positive and non-integer RUNS/RUN_TIMEOUT_SEC deterministically"
