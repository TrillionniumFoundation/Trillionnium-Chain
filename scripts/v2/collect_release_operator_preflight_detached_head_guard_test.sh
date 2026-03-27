#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/scripts/v2/collect_release_operator_preflight.sh"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing script: $TARGET" >&2
  exit 1
fi

required_lines=(
  'if [[ -z "$CURRENT_BRANCH" ]]; then'
  'detached HEAD is not allowed; check out the lane branch before collecting operator preflight evidence'
  'exit 1'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing detached-head guard line: $line" >&2
    exit 1
  fi
done

echo "[PASS] collect_release_operator_preflight.sh rejects detached HEAD operator preflight capture"
