#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/v2/verify_lane_worktree.sh"
EXPECTED_BRANCH="$(git -C "$ROOT" branch --show-current)"
EXPECTED_HEAD="$(git -C "$ROOT" rev-parse HEAD)"

if [[ -z "$EXPECTED_BRANCH" ]]; then
  echo "[FAIL] expected a checked-out branch for the fixture worktree" >&2
  exit 1
fi

TMPDIR_FIXTURE="$ROOT/.tmp/verify_lane_worktree_canonical_worktree_root_test"
trap 'rm -rf "$TMPDIR_FIXTURE"' EXIT
mkdir -p "$TMPDIR_FIXTURE"
SYMLINK_ROOT="$TMPDIR_FIXTURE/worktree-link"
ln -s "$ROOT" "$SYMLINK_ROOT"

output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$SYMLINK_ROOT" \
  --expected-branch "$EXPECTED_BRANCH" \
  --expected-head "$EXPECTED_HEAD")"

printf '%s\n' "$output" | grep -Fqx "[OK] worktree_root=$ROOT branch=$EXPECTED_BRANCH branch_ref=refs/heads/$EXPECTED_BRANCH head=$EXPECTED_HEAD"

echo "[PASS] verify_lane_worktree.sh canonicalizes expected worktree roots before fail-closed comparison"
