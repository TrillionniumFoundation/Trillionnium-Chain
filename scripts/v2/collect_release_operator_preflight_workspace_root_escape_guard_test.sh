#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/collect_release_operator_preflight.sh"
EXPECTED_WORKTREE_ROOT="$ROOT"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
EXPECTED_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"

set +e
output="$(cd "$ROOT" && WORKSPACE_ROOT=/tmp "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" 2>&1)"
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "[FAIL] expected workspace_root escape to fail closed" >&2
  exit 1
fi

printf '%s\n' "$output" | grep -Fq "[FAIL] workspace root escapes worktree root: workspace_root=/private/tmp worktree_root=$ROOT"

echo "[PASS] collect_release_operator_preflight.sh rejects workspace_root values outside the current worktree"
