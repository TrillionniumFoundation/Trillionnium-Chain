#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/collect_release_operator_preflight.sh"

EXPECTED_WORKTREE_ROOT="$ROOT"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
BAD_BRANCH_REF="refs/heads/not-$EXPECTED_BRANCH"

if [[ -z "$EXPECTED_BRANCH" ]]; then
  echo "[FAIL] expected a checked-out branch for the fixture worktree" >&2
  exit 1
fi

set +e
output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch "$EXPECTED_BRANCH" \
  --expected-branch-ref "$BAD_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" 2>&1)"
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "[FAIL] expected canonical branch/ref mismatch to fail closed" >&2
  exit 1
fi

printf '%s\n' "$output" | grep -Fq "[FAIL] expected branch/ref mismatch: branch=$EXPECTED_BRANCH branch_ref=$BAD_BRANCH_REF canonical_ref=refs/heads/$EXPECTED_BRANCH"

echo "[PASS] collect_release_operator_preflight.sh rejects mismatched branch + branch-ref inputs before evidence capture"
