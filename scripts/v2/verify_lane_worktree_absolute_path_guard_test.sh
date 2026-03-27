#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/verify_lane_worktree.sh"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"

if [[ -z "$EXPECTED_BRANCH" ]]; then
  echo "[FAIL] expected a checked-out branch for the fixture worktree" >&2
  exit 1
fi

set +e
output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root . \
  --expected-branch "$EXPECTED_BRANCH" 2>&1)"
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "[FAIL] expected relative worktree root to be rejected" >&2
  exit 1
fi

printf '%s\n' "$output" | grep -Fq '[FAIL] --expected-worktree-root must be an absolute path: .'

echo "[PASS] verify_lane_worktree.sh rejects relative expected worktree roots fail-closed"
