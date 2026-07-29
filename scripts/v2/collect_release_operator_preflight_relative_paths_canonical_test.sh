#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/collect_release_operator_preflight.sh"

EXPECTED_WORKTREE_ROOT="$ROOT"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
EXPECTED_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"
WORKSPACE_ROOT="$ROOT"
if [[ -f "$ROOT/trillionnium/Cargo.toml" ]]; then
  WORKSPACE_ROOT="$ROOT/trillionnium"
fi

output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" \
  --binary-path target/debug/trnm-cometbft-app \
  --cli-binary-path ../trillionnium/target/debug/trnm-cli \
  --rollback-entrypoint scripts/devnet_down.sh)"

printf '%s\n' "$output" | grep -Fqx "binary_path=$WORKSPACE_ROOT/target/debug/trnm-cometbft-app"
printf '%s\n' "$output" | grep -Fqx "cli_binary_path=$ROOT/trillionnium/target/debug/trnm-cli"
printf '%s\n' "$output" | grep -Fqx "rollback_entrypoint=$ROOT/scripts/devnet_down.sh"

echo "[PASS] collect_release_operator_preflight.sh canonicalizes relative binary, CLI, and rollback paths into absolute worktree-scoped evidence"
