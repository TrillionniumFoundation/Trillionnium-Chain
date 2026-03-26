#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/scripts/v2/verify_lane_worktree.sh"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing script: $TARGET" >&2
  exit 1
fi

required_lines=(
  '--expected-branch-ref <refs/heads/...>'
  'EXPECTED_BRANCH_REF=""'
  '--expected-branch-ref)'
  'pass either --expected-branch or --expected-branch-ref, not both'
  'one of --expected-branch or --expected-branch-ref is required'
  'ACTUAL_BRANCH_REF="refs/heads/$ACTUAL_BRANCH"'
  'branch-ref mismatch: expected $EXPECTED_BRANCH_REF got $ACTUAL_BRANCH_REF'
  "printf '[OK] worktree_root=%s branch=%s branch_ref=%s head=%s\\n'"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$TARGET"; then
    echo "[FAIL] missing branch-ref guard line: $line" >&2
    exit 1
  fi
done

echo "[PASS] verify_lane_worktree.sh supports explicit branch-ref fail-closed validation"
