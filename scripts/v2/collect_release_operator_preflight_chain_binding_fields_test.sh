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
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" \
  --chain-id trnm-devnet-1 \
  --genesis-sha256 abcdef1234567890)"

printf '%s\n' "$output" | grep -Fqx 'chain_id=trnm-devnet-1'
printf '%s\n' "$output" | grep -Fqx 'genesis_sha256=abcdef1234567890'

echo "[PASS] collect_release_operator_preflight.sh binds chain_id and genesis_sha256 into operator handoff evidence"
