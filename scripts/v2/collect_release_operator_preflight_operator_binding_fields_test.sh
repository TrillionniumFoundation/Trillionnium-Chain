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
EXPECTED_VALIDATOR_COUNT="$(find "$WORKSPACE_ROOT/configs" -maxdepth 1 -type f -name 'node*.toml' 2>/dev/null | wc -l | awk '{print $1}')"

output="$(cd "$ROOT" && "$SCRIPT" \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  --expected-head "$EXPECTED_HEAD")"

printf '%s\n' "$output" | grep -Fqx 'window_type=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'change_ticket=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'started_at_utc=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'config_set_id=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'chain_id=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'genesis_path=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'genesis_sha256=<fill-me>'
printf '%s\n' "$output" | grep -Fqx "validator_count=$EXPECTED_VALIDATOR_COUNT"
printf '%s\n' "$output" | grep -Fqx 'seed_mode=<fill-me>'
printf '%s\n' "$output" | grep -Fqx 'p2p_allowlist_source=<fill-me>'

echo "[PASS] collect_release_operator_preflight.sh binds run identity plus exact genesis-path/config-set and peer-source fields into operator handoff evidence"
