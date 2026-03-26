#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  collect_release_operator_preflight.sh \
    [--operator-id <id>] \
    [--binary-path <path>] \
    [--binary-build-command <cmd>] \
    [--cli-binary-path <path>] \
    [--cli-build-command <cmd>] \
    [--previous-stable-anchor <commit-or-tag>] \
    [--rollback-entrypoint <path-or-command>] \
    [--expected-worktree-root <abs-path>] \
    [--expected-branch <branch>] \
    [--expected-branch-ref <refs/heads/...>] \
    [--expected-head <commit>]

Prints a fail-closed release/operator preflight record for the current lane worktree.
When expected lane arguments are supplied, this script first calls
scripts/v2/verify_lane_worktree.sh and aborts on mismatch.
EOF
}

ROOT="$(git rev-parse --show-toplevel)"
VERIFY_SCRIPT="$ROOT/scripts/v2/verify_lane_worktree.sh"
WORKSPACE_ROOT="$ROOT"
CURRENT_BRANCH=""
CURRENT_HEAD=""
WORKTREE_STATUS=""
OPERATOR_ID="${OPERATOR_ID:-<fill-me>}"
BINARY_PATH="${BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-node}"
BINARY_BUILD_COMMAND="${BINARY_BUILD_COMMAND:-cargo build -p trnm-node}"
CLI_BINARY_PATH="${CLI_BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-cli}"
CLI_BUILD_COMMAND="${CLI_BUILD_COMMAND:-cargo build -p trnm-cli}"
PREVIOUS_STABLE_ANCHOR="${PREVIOUS_STABLE_ANCHOR:-<fill-me>}"
ROLLBACK_ENTRYPOINT="${ROLLBACK_ENTRYPOINT:-./scripts/devnet_down.sh}"
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH=""
EXPECTED_BRANCH_REF=""
EXPECTED_HEAD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-id)
      OPERATOR_ID="${2:-}"
      shift 2
      ;;
    --binary-path)
      BINARY_PATH="${2:-}"
      shift 2
      ;;
    --binary-build-command)
      BINARY_BUILD_COMMAND="${2:-}"
      shift 2
      ;;
    --cli-binary-path)
      CLI_BINARY_PATH="${2:-}"
      shift 2
      ;;
    --cli-build-command)
      CLI_BUILD_COMMAND="${2:-}"
      shift 2
      ;;
    --previous-stable-anchor)
      PREVIOUS_STABLE_ANCHOR="${2:-}"
      shift 2
      ;;
    --rollback-entrypoint)
      ROLLBACK_ENTRYPOINT="${2:-}"
      shift 2
      ;;
    --expected-worktree-root)
      EXPECTED_WORKTREE_ROOT="${2:-}"
      shift 2
      ;;
    --expected-branch)
      EXPECTED_BRANCH="${2:-}"
      shift 2
      ;;
    --expected-branch-ref)
      EXPECTED_BRANCH_REF="${2:-}"
      shift 2
      ;;
    --expected-head)
      EXPECTED_HEAD="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[FAIL] unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "$EXPECTED_WORKTREE_ROOT" || -n "$EXPECTED_BRANCH" || -n "$EXPECTED_BRANCH_REF" || -n "$EXPECTED_HEAD" ]]; then
  VERIFY_ARGS=()
  if [[ -n "$EXPECTED_WORKTREE_ROOT" ]]; then
    VERIFY_ARGS+=(--expected-worktree-root "$EXPECTED_WORKTREE_ROOT")
  fi
  if [[ -n "$EXPECTED_BRANCH" ]]; then
    VERIFY_ARGS+=(--expected-branch "$EXPECTED_BRANCH")
  fi
  if [[ -n "$EXPECTED_BRANCH_REF" ]]; then
    VERIFY_ARGS+=(--expected-branch-ref "$EXPECTED_BRANCH_REF")
  fi
  if [[ -n "$EXPECTED_HEAD" ]]; then
    VERIFY_ARGS+=(--expected-head "$EXPECTED_HEAD")
  fi
  "$VERIFY_SCRIPT" "${VERIFY_ARGS[@]}" >/dev/null
fi

CURRENT_BRANCH="$(git branch --show-current)"
CURRENT_HEAD="$(git rev-parse HEAD)"
WORKTREE_STATUS="$(test -z "$(git status --short)" && echo clean || echo dirty)"

printf 'operator_id=%s\n' "$OPERATOR_ID"
printf 'worktree_root=%s\n' "$ROOT"
printf 'workspace_root=%s\n' "$WORKSPACE_ROOT"
printf 'branch=%s\n' "$CURRENT_BRANCH"
printf 'branch_ref=%s\n' "refs/heads/$CURRENT_BRANCH"
printf 'head_sha=%s\n' "$CURRENT_HEAD"
printf 'commit_short=%s\n' "${CURRENT_HEAD:0:9}"
printf 'worktree_status=%s\n' "$WORKTREE_STATUS"
printf 'binary_path=%s\n' "$BINARY_PATH"
printf 'binary_sha256=%s\n' "$(if [[ -x "$BINARY_PATH" ]]; then shasum -a 256 "$BINARY_PATH" | awk '{print $1}'; else printf '<not-built>'; fi)"
printf 'build_command=%s\n' "$BINARY_BUILD_COMMAND"
printf 'cli_binary_path=%s\n' "$CLI_BINARY_PATH"
printf 'cli_binary_sha256=%s\n' "$(if [[ -x "$CLI_BINARY_PATH" ]]; then shasum -a 256 "$CLI_BINARY_PATH" | awk '{print $1}'; else printf '<not-built>'; fi)"
printf 'cli_build_command=%s\n' "$CLI_BUILD_COMMAND"
printf 'previous_stable_anchor=%s\n' "$PREVIOUS_STABLE_ANCHOR"
printf 'rollback_entrypoint=%s\n' "$ROLLBACK_ENTRYPOINT"
