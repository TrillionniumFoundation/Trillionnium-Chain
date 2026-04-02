#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: run_validator_dr_rehearsal.sh \
  --expected-worktree-root <path> \
  --expected-branch-ref <ref> \
  [--expected-head <sha>]

Run one fail-closed validator DR rehearsal for the current lane by chaining:
  1. verify_lane_worktree.sh
  2. check_bft_restart_recovery.sh
  3. extract_validator_rotation_dr_fields.sh

This wrapper exists so operators can capture one deterministic DR evidence block
without reconstructing report paths or shell snippets from memory.
`--expected-branch-ref` accepts either a short branch name (for example
`lane/foo`) or a full ref (for example `refs/heads/lane/foo`).
EOF
}

EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_HEAD=""

require_nonempty() {
  local flag_name="$1"
  local value="$2"
  [ -n "$value" ] || {
    printf 'missing %s\n' "$flag_name" >&2
    usage
    exit 2
  }
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --expected-worktree-root)
      [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }
      EXPECTED_WORKTREE_ROOT="$2"
      shift 2
      ;;
    --expected-branch-ref)
      [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }
      EXPECTED_BRANCH_REF="$2"
      shift 2
      ;;
    --expected-head)
      [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }
      EXPECTED_HEAD="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

require_nonempty --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
require_nonempty --expected-branch-ref "$EXPECTED_BRANCH_REF"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

verify_args=(
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
)
extract_args=(
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
)

if [ -n "$EXPECTED_HEAD" ]; then
  verify_args+=(--expected-head "$EXPECTED_HEAD")
  extract_args+=(--expected-head "$EXPECTED_HEAD")
fi

./scripts/v2/verify_lane_worktree.sh "${verify_args[@]}" >/dev/null

recovery_stdout="$({
  EXPECTED_WORKTREE_ROOT="$EXPECTED_WORKTREE_ROOT" \
  EXPECTED_BRANCH_REF="$EXPECTED_BRANCH_REF" \
  EXPECTED_HEAD="$EXPECTED_HEAD" \
  ./scripts/check_bft_restart_recovery.sh
} 2>&1)"
printf '%s\n' "$recovery_stdout" >&2

report_path="$(printf '%s\n' "$recovery_stdout" | sed -n 's/^\[OK\] bft restart recovery passed: //p' | tail -n 1)"
[ -n "$report_path" ] || {
  echo "missing recovery report path from check_bft_restart_recovery.sh output" >&2
  exit 1
}

./scripts/v2/extract_validator_rotation_dr_fields.sh \
  --report-path "$report_path" \
  "${extract_args[@]}"
