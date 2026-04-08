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
  --expected-head "$EXPECTED_HEAD")"

for node in 1 2 3 4; do
  config_path="$WORKSPACE_ROOT/configs/node${node}.toml"
  expected_sha="<not-found>"
  if [[ -f "$config_path" ]]; then
    expected_sha="$(shasum -a 256 "$config_path" | awk '{print $1}')"
  fi
  printf '%s\n' "$output" | grep -Fqx "node${node}_config_sha256=$expected_sha"
done

tmp_workspace="$ROOT/.tmp/collect_release_operator_preflight_config_hashes_test"
trap 'rm -rf "$tmp_workspace"' EXIT
mkdir -p "$tmp_workspace/configs"
printf 'node1\n' > "$tmp_workspace/configs/node1.toml"
printf 'node3\n' > "$tmp_workspace/configs/node3.toml"

partial_output="$(cd "$ROOT" && WORKSPACE_ROOT="$tmp_workspace" "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD" \
  --validator-count 3)"

node1_sha="$(shasum -a 256 "$tmp_workspace/configs/node1.toml" | awk '{print $1}')"
node3_sha="$(shasum -a 256 "$tmp_workspace/configs/node3.toml" | awk '{print $1}')"
printf '%s\n' "$partial_output" | grep -Fqx "node1_config_sha256=$node1_sha"
printf '%s\n' "$partial_output" | grep -Fqx 'node2_config_sha256=<not-found>'
printf '%s\n' "$partial_output" | grep -Fqx "node3_config_sha256=$node3_sha"
printf '%s\n' "$partial_output" | grep -Fqx 'node4_config_sha256=<not-used>'

echo "[PASS] collect_release_operator_preflight.sh binds node config sha256 values and distinguishes missing vs intentionally unused validator slots"
