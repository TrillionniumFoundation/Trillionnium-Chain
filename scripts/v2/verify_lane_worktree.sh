#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  verify_lane_worktree.sh --expected-worktree-root <abs-path> [--expected-branch <branch> | --expected-branch-ref <refs/heads/...>] [--expected-head <commit>]

Verifies that the current repository worktree root and checked-out branch match the
expected lane context. Optionally pins the exact HEAD commit for evidence capture.
EOF
}

EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH=""
EXPECTED_BRANCH_REF=""
EXPECTED_HEAD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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

if [[ -z "$EXPECTED_WORKTREE_ROOT" ]]; then
  echo "[FAIL] --expected-worktree-root is required" >&2
  usage >&2
  exit 1
fi

if [[ -n "$EXPECTED_BRANCH" && -n "$EXPECTED_BRANCH_REF" ]]; then
  echo "[FAIL] pass either --expected-branch or --expected-branch-ref, not both" >&2
  usage >&2
  exit 1
fi

if [[ -z "$EXPECTED_BRANCH" && -z "$EXPECTED_BRANCH_REF" ]]; then
  echo "[FAIL] one of --expected-branch or --expected-branch-ref is required" >&2
  usage >&2
  exit 1
fi

if [[ ! -d "$EXPECTED_WORKTREE_ROOT" ]]; then
  echo "[FAIL] expected worktree root does not exist: $EXPECTED_WORKTREE_ROOT" >&2
  exit 1
fi

ACTUAL_WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
ACTUAL_BRANCH="$(git branch --show-current)"
ACTUAL_BRANCH_REF=""
ACTUAL_HEAD="$(git rev-parse HEAD)"

if [[ -z "$ACTUAL_BRANCH" ]]; then
  echo "[FAIL] detached HEAD is not allowed; check out the lane branch before collecting evidence" >&2
  exit 1
fi

if [[ -n "$ACTUAL_BRANCH" ]]; then
  ACTUAL_BRANCH_REF="refs/heads/$ACTUAL_BRANCH"
fi

if [[ "$ACTUAL_WORKTREE_ROOT" != "$EXPECTED_WORKTREE_ROOT" ]]; then
  echo "[FAIL] worktree mismatch: expected $EXPECTED_WORKTREE_ROOT got $ACTUAL_WORKTREE_ROOT" >&2
  exit 1
fi

if [[ -n "$EXPECTED_BRANCH" && "$ACTUAL_BRANCH" != "$EXPECTED_BRANCH" ]]; then
  echo "[FAIL] branch mismatch: expected $EXPECTED_BRANCH got $ACTUAL_BRANCH" >&2
  exit 1
fi

if [[ -n "$EXPECTED_BRANCH_REF" && "$ACTUAL_BRANCH_REF" != "$EXPECTED_BRANCH_REF" ]]; then
  echo "[FAIL] branch-ref mismatch: expected $EXPECTED_BRANCH_REF got $ACTUAL_BRANCH_REF" >&2
  exit 1
fi

if [[ -n "$EXPECTED_HEAD" && "$ACTUAL_HEAD" != "$EXPECTED_HEAD" ]]; then
  echo "[FAIL] HEAD mismatch: expected $EXPECTED_HEAD got $ACTUAL_HEAD" >&2
  exit 1
fi

printf '[OK] worktree_root=%s branch=%s branch_ref=%s head=%s\n' "$ACTUAL_WORKTREE_ROOT" "$ACTUAL_BRANCH" "$ACTUAL_BRANCH_REF" "$ACTUAL_HEAD"
