#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
export LANG=C
export TZ=UTC

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/check_parallel_flaky.sh"

if [[ ! -f "$SCRIPT" ]]; then
  echo "[FAIL] missing script: $SCRIPT" >&2
  exit 1
fi

guard='timeout binary not found (need timeout or gtimeout)'
count=$(grep -Fc -- "$guard" "$SCRIPT" || true)
if [[ "$count" -lt 2 ]]; then
  echo "[FAIL] expected CI timeout-binary guard in both runner and replay template" >&2
  exit 1
fi

echo "[PASS] check_parallel_flaky replay template includes CI timeout-binary guard"
