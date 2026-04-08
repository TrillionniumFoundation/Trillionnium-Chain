#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/check_parallel_flaky.sh"

if [[ ! -f "$SCRIPT" ]]; then
  echo "[FAIL] missing script: $SCRIPT" >&2
  exit 1
fi

set +e
out="$(RUNS=1 RUN_TIMEOUT_SEC=abc /bin/bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ "$rc" -ne 64 ]]; then
  echo "[FAIL] expected invalid input guard exit code 64, got $rc" >&2
  echo "$out" >&2
  exit 1
fi

if [[ "$out" != *"RUN_TIMEOUT_SEC must be a positive integer (got: abc)"* ]]; then
  echo "[FAIL] missing RUN_TIMEOUT_SEC input guard message" >&2
  echo "$out" >&2
  exit 1
fi

echo "[PASS] check_parallel_flaky rejects non-numeric RUN_TIMEOUT_SEC before execution"
