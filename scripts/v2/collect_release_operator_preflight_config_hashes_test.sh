#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/collect_release_operator_preflight.sh"

EXPECTED_WORKTREE_ROOT="$ROOT"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
EXPECTED_BRANCH_REF="refs/heads/$EXPECTED_BRANCH"
WORKSPACE_ROOT="$ROOT"
if [[ -f "$ROOT/trillionnium-rust/Cargo.toml" ]]; then
  WORKSPACE_ROOT="$ROOT/trillionnium-rust"
fi

output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD")"

for node in 1 2 3 4; do
  config_path="$WORKSPACE_ROOT/configs/node${node}.toml"
  expected_sha="<not-found>"
  if [[ -f "$config_path" ]]; then
    expected_sha="$(shasum -a 256 "$config_path" | awk '{print $1}')"
  fi
  printf '%s\n' "$output" | grep -Fqx "node${node}_config_sha256=$expected_sha"
done

echo "[PASS] collect_release_operator_preflight.sh binds node config sha256 values into operator handoff evidence"
