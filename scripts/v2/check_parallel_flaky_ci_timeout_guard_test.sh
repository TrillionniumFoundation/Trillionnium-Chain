#!/usr/bin/env bash
set -euo pipefail

# Stabilize locale/time behavior across CI runners for deterministic stderr matching.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export LC_NUMERIC=C
export TZ=UTC

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/check_parallel_flaky.sh"

if [[ ! -f "$SCRIPT" ]]; then
  echo "[FAIL] missing script: $SCRIPT" >&2
  exit 1
fi

set +e
out="$(env CI=1 PATH=/nonexistent RUNS=1 RUN_TIMEOUT_SEC=1 /bin/bash "$SCRIPT" 2>&1)"
rc=$?
set -e

if [[ "$rc" -ne 69 ]]; then
  echo "[FAIL] expected CI timeout guard exit code 69, got $rc" >&2
  echo "$out" >&2
  exit 1
fi

if [[ "$out" != *"timeout binary not found (need timeout or gtimeout)"* ]]; then
  echo "[FAIL] missing timeout guard message" >&2
  echo "$out" >&2
  exit 1
fi

echo "[PASS] check_parallel_flaky enforces CI timeout binary guard before run setup"
