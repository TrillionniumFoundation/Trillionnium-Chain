#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/scripts/v2/verify_lane_worktree.sh"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing script: $TARGET" >&2
  exit 1
fi

required_lines=(
  'detached HEAD is not allowed; check out the lane branch before collecting evidence'
  'if [[ -z "$ACTUAL_BRANCH" ]]; then'
  'exit 1'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing detached-head guard line: $line" >&2
    exit 1
  fi
done

echo "[PASS] verify_lane_worktree.sh rejects detached HEAD evidence capture"
