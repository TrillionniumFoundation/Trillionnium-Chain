#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/collect_release_operator_preflight.sh"

EXPECTED_WORKTREE_ROOT="$ROOT"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
EXPECTED_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"
EXPECTED_WORKSPACE_ROOT="$ROOT"
if [[ -f "$ROOT/trillionnium/Cargo.toml" ]]; then
  EXPECTED_WORKSPACE_ROOT="$ROOT/trillionnium"
fi

output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD")"

printf '%s\n' "$output" | grep -Fqx "workspace_root=$EXPECTED_WORKSPACE_ROOT"
printf '%s\n' "$output" | grep -Fqx "binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-node"
printf '%s\n' "$output" | grep -Fqx "cli_binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-cli"
printf '%s\n' "$output" | grep -Fqx "rollback_entrypoint=$ROOT/scripts/devnet_down.sh"

echo "[PASS] collect_release_operator_preflight.sh defaults workspace_root, binary paths, and rollback entrypoint to canonical worktree-scoped paths"
