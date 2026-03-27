#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/collect_release_operator_preflight.sh"

EXPECTED_WORKTREE_ROOT="$ROOT"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
EXPECTED_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"

output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch "$EXPECTED_BRANCH" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD")"

printf '%s\n' "$output" | grep -Fqx "branch=$EXPECTED_BRANCH"
printf '%s\n' "$output" | grep -Fqx "branch_ref=$EXPECTED_BRANCH_REF"
printf '%s\n' "$output" | grep -Fqx "head_sha=$EXPECTED_HEAD"

echo "[PASS] collect_release_operator_preflight.sh accepts matching branch + branch-ref inputs and normalizes verification fail-closed"
