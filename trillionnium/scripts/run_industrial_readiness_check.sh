#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export TZ="${TZ:-UTC}"
export LC_ALL="${LC_ALL:-C}"
export LANG="${LANG:-C}"

normalize_branch_ref() {
  case "$1" in
    refs/*) printf '%s\n' "$1" ;;
    *) printf 'refs/heads/%s\n' "$1" ;;
  esac
}

OWNER="${1:-ProfAlexQI}"
REPO="${2:-TrillionniumChain}"
REQUIRED_STREAK="${3:-3}"
case "$REQUIRED_STREAK" in
  ''|*[!0-9]*)
    echo "REQUIRED_STREAK must be a positive integer, got '$REQUIRED_STREAK'" >&2
    exit 64
    ;;
esac
if [ "$REQUIRED_STREAK" -lt 1 ]; then
  echo "REQUIRED_STREAK must be >= 1, got '$REQUIRED_STREAK'" >&2
  exit 64
fi

GIT_TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null || echo unknown)"
GIT_BRANCH_RAW="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
if [ "$GIT_BRANCH_RAW" = "HEAD" ]; then
  GIT_BRANCH="<detached-HEAD>"
  GIT_HEAD_STATE="detached"
else
  GIT_BRANCH="$GIT_BRANCH_RAW"
  GIT_HEAD_STATE="attached"
fi
GIT_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_STATUS_SHORT="$(git status --short 2>/dev/null || true)"
if [ -z "$GIT_STATUS_SHORT" ]; then
  GIT_STATUS_SUMMARY="clean"
else
  GIT_STATUS_SUMMARY="dirty"
fi
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain 2>/dev/null | awk -v target="$GIT_TOPLEVEL" '
  BEGIN { in_match=0 }
  /^worktree / {
    path = substr($0, length("worktree ") + 1)
    in_match = (path == target)
  }
  in_match { print }
  in_match && /^$/ { exit }
' || true)"
if [ -n "$CURRENT_WORKTREE_ENTRY" ]; then
  CURRENT_WORKTREE_BRANCH_REF="$(printf '%s\n' "$CURRENT_WORKTREE_ENTRY" | awk '/^branch / { print $2; exit }')"
else
  CURRENT_WORKTREE_BRANCH_REF=""
fi

lane_verify_command="<not-run>"
if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ] || [ -n "${EXPECTED_BRANCH_REF:-}" ] || [ -n "${EXPECTED_HEAD:-}" ]; then
  [ -n "${EXPECTED_WORKTREE_ROOT:-}" ] || { echo "lane identity failed: EXPECTED_WORKTREE_ROOT is required when lane binding is enabled" >&2; exit 4; }
  [ -n "${EXPECTED_BRANCH_REF:-}" ] || { echo "lane identity failed: EXPECTED_BRANCH_REF is required when lane binding is enabled" >&2; exit 4; }
  EXPECTED_BRANCH_REF="$(normalize_branch_ref "$EXPECTED_BRANCH_REF")"
  lane_verify_args=(
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
    --expected-branch-ref "$EXPECTED_BRANCH_REF"
  )
  if [ -n "${EXPECTED_HEAD:-}" ]; then
    lane_verify_args+=(--expected-head "$EXPECTED_HEAD")
  fi
  lane_verify_command="./scripts/v2/verify_lane_worktree.sh"
  for arg in "${lane_verify_args[@]}"; do
    printf -v quoted_arg '%q' "$arg"
    lane_verify_command+=" $quoted_arg"
  done
  ./scripts/v2/verify_lane_worktree.sh "${lane_verify_args[@]}"
fi

OUT_DIR="$ROOT/run/health"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%d-%H%M%S)"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUT_FILE="$OUT_DIR/industrial-readiness-${TS}.txt"
REPLAY_COMMAND="env TZ='${TZ}' LC_ALL='${LC_ALL}' LANG='${LANG}'"
if [ -n "${EXPECTED_WORKTREE_ROOT:-}" ]; then
  REPLAY_COMMAND+=" EXPECTED_WORKTREE_ROOT='${EXPECTED_WORKTREE_ROOT}'"
fi
if [ -n "${EXPECTED_BRANCH_REF:-}" ]; then
  REPLAY_COMMAND+=" EXPECTED_BRANCH_REF='${EXPECTED_BRANCH_REF}'"
fi
if [ -n "${EXPECTED_HEAD:-}" ]; then
  REPLAY_COMMAND+=" EXPECTED_HEAD='${EXPECTED_HEAD}'"
fi
if [ -n "${EXPECTED_BRANCH_REF:-}" ]; then
  EXPECTED_BRANCH_REF="$(normalize_branch_ref "$EXPECTED_BRANCH_REF")"
fi
REPLAY_COMMAND+=" ./scripts/run_industrial_readiness_check.sh $(printf '%q' "$OWNER") $(printf '%q' "$REPO") $(printf '%q' "$REQUIRED_STREAK")"
ROLLBACK_COMMAND="rm -f $(printf '%q' "$OUT_FILE")"

{
  echo "industrial_readiness.ts=$TS"
  echo "industrial_readiness.generated_at=$GENERATED_AT"
  echo "industrial_readiness.owner=$OWNER"
  echo "industrial_readiness.repo=$REPO"
  echo "industrial_readiness.required_streak=$REQUIRED_STREAK"
  echo "industrial_readiness.git_toplevel=$GIT_TOPLEVEL"
  echo "industrial_readiness.git_branch=$GIT_BRANCH"
  echo "industrial_readiness.git_head=$GIT_HEAD"
  echo "industrial_readiness.git_head_state=$GIT_HEAD_STATE"
  echo "industrial_readiness.git_status_summary=$GIT_STATUS_SUMMARY"
  echo "industrial_readiness.git_worktree_branch_ref=${CURRENT_WORKTREE_BRANCH_REF:-<detached-or-unbound>}"
  echo "industrial_readiness.expected_worktree_root=${EXPECTED_WORKTREE_ROOT:-<unset>}"
  echo "industrial_readiness.expected_branch_ref=${EXPECTED_BRANCH_REF:-<unset>}"
  echo "industrial_readiness.expected_head=${EXPECTED_HEAD:-<unset>}"
  echo "industrial_readiness.lane_verify_command=$lane_verify_command"
  echo "industrial_readiness.replay_command=$REPLAY_COMMAND"
  echo "industrial_readiness.rollback_command=$ROLLBACK_COMMAND"
  ./scripts/check_nightly_green_streak.sh "$OWNER" "$REPO" "$REQUIRED_STREAK"
  echo "industrial_readiness.result=PASS"
} | tee "$OUT_FILE"

echo "[OK] industrial readiness report: $OUT_FILE"
