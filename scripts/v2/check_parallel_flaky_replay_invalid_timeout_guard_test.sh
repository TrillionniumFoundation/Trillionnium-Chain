#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/check_parallel_flaky.sh"

if [[ ! -f "$SCRIPT" ]]; then
  echo "[FAIL] missing script: $SCRIPT" >&2
  exit 1
fi

guard='RUN_TIMEOUT_SEC must be a positive integer (got: $RUN_TIMEOUT_SEC)'
count=$(grep -Fc -- "$guard" "$SCRIPT" || true)
if [[ "$count" -lt 2 ]]; then
  echo "[FAIL] expected RUN_TIMEOUT_SEC guard message in both runner and replay template" >&2
  exit 1
fi

echo "[PASS] check_parallel_flaky replay template includes RUN_TIMEOUT_SEC numeric guard"