#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: extract_validator_rotation_dr_fields.sh [--report-path <path>] \
  [--expected-worktree-root <path>] [--expected-branch-ref <ref>] [--expected-head <sha>]

Resolve the latest validator DR recovery report (unless --report-path is
provided), then print the canonical fields required by the validator
replacement/rotation/DR handoff. This helper fails closed on missing report
paths, missing required keys, non-PASS recovery status, or lane/worktree
identity drift when explicit expectations are provided.
`--expected-worktree-root` and `--expected-branch-ref` must be provided
as a pair when lane binding is expected.
`--expected-branch-ref` accepts either a short branch name (for example
`lane/foo`) or a full ref (for example `refs/heads/lane/foo`).
EOF
}

REPORT_PATH=""
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_BRANCH_REF_CANONICAL=""
EXPECTED_HEAD=""

require_nonempty_value() {
  local flag_name="$1"
  local value="$2"

  [ -n "$value" ] || {
    printf 'missing %s\n' "$flag_name" >&2
    usage
    exit 2
  }
}

require_worktree_root_value() {
  local flag_name="$1"
  local value="$2"

  require_nonempty_value "$flag_name" "$value"

  case "$value" in
    [[:space:]]*|*[[:space:]])
      printf 'invalid %s: must not start or end with whitespace: %q\n' "$flag_name" "$value" >&2
      exit 2
      ;;
  esac

  case "$value" in
    *[$'\001'-$'\037']*|*$'\177'*)
      printf 'invalid %s: must not contain control characters\n' "$flag_name" >&2
      exit 2
      ;;
  esac
}

require_ref_token() {
  local flag_name="$1"
  local value="$2"

  require_nonempty_value "$flag_name" "$value"

  case "$value" in
    *[[:space:]]*)
      printf 'invalid %s: must not contain whitespace: %s\n' "$flag_name" "$value" >&2
      exit 2
      ;;
  esac
}

canonicalize_path() {
  local input="$1"
  (
    cd "$input" >/dev/null 2>&1 && pwd -P
  )
}

canonicalize_branch_ref() {
  local ref="$1"
  case "$ref" in
    refs/*)
      printf '%s' "$ref"
      ;;
    *)
      printf 'refs/heads/%s' "$ref"
      ;;
  esac
}

require_key() {
  local path="$1"
  local key="$2"
  local value

  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path")"
  [ -n "$value" ] || { printf 'missing %s in %s\n' "$key" "$path" >&2; exit 1; }
  printf '%s' "$value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --report-path)
      [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }
      REPORT_PATH="$2"
      shift 2
      ;;
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

if [ -n "$EXPECTED_WORKTREE_ROOT" ] || [ -n "$EXPECTED_BRANCH_REF" ]; then
  if [ -z "$EXPECTED_WORKTREE_ROOT" ] || [ -z "$EXPECTED_BRANCH_REF" ]; then
    printf 'lane binding requires both --expected-worktree-root and --expected-branch-ref together\n' >&2
    usage
    exit 2
  fi
  require_worktree_root_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
  require_ref_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
  EXPECTED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")"
  case "$EXPECTED_BRANCH_REF_CANONICAL" in
    refs/heads/*) ;;
    *)
      printf 'invalid --expected-branch-ref: expected refs/heads/* got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" >&2
      exit 2
      ;;
  esac
fi
if [ -n "$EXPECTED_HEAD" ]; then
  require_ref_token --expected-head "$EXPECTED_HEAD"
fi

ROOT="$(git rev-parse --show-toplevel)"
RUN_ROOT="$ROOT/run"
RUN_ROOT_CANONICAL="$(canonicalize_path "$RUN_ROOT")" || {
  printf 'run directory is not accessible: %s\n' "$RUN_ROOT" >&2
  exit 1
}

if [ -z "$REPORT_PATH" ]; then
  REPORT_PATH="$(find "$RUN_ROOT" -maxdepth 1 -type f -name 'bft-restart-recovery-*.txt' -print 2>/dev/null | sort | tail -n 1)"
fi

[ -n "$REPORT_PATH" ] || { echo "missing recovery report under $RUN_ROOT" >&2; exit 1; }
[ -f "$REPORT_PATH" ] || { echo "missing recovery report file: $REPORT_PATH" >&2; exit 1; }

REPORT_PATH_CANONICAL="$(canonicalize_path "$(dirname "$REPORT_PATH")")/$(basename "$REPORT_PATH")"
case "$REPORT_PATH_CANONICAL" in
  "$RUN_ROOT_CANONICAL"/bft-restart-recovery-*.txt) ;;
  *)
    printf 'recovery report must live under current worktree run/: %s\n' "$REPORT_PATH_CANONICAL" >&2
    exit 1
    ;;
 esac
REPORT_PATH="$REPORT_PATH_CANONICAL"

GENERATED_AT="$(require_key "$REPORT_PATH" generated_at)"
CONFIG_PATH="$(require_key "$REPORT_PATH" config_path)"
GIT_WORKTREE_PATH="$(require_key "$REPORT_PATH" git_worktree_path)"
GIT_WORKTREE_BRANCH_REF="$(require_key "$REPORT_PATH" git_worktree_branch_ref)"
GIT_BRANCH="$(require_key "$REPORT_PATH" git_branch)"
GIT_HEAD="$(require_key "$REPORT_PATH" git_head)"
GIT_STATUS_SUMMARY="$(require_key "$REPORT_PATH" git_status_summary)"
ROLLBACK_COMMAND="$(require_key "$REPORT_PATH" rollback_command)"
REPLAY_COMMAND="$(require_key "$REPORT_PATH" replay_command)"
STATUS="$(require_key "$REPORT_PATH" status)"

if [ "$GIT_STATUS_SUMMARY" != "clean" ]; then
  printf 'report git_status_summary must be clean, got %s from %s\n' "$GIT_STATUS_SUMMARY" "$REPORT_PATH" >&2
  exit 1
fi

if [ "$STATUS" != "PASS" ]; then
  printf 'report status must be PASS, got %s from %s\n' "$STATUS" "$REPORT_PATH" >&2
  exit 1
fi

if [ -n "$EXPECTED_WORKTREE_ROOT" ] && [ "$GIT_WORKTREE_PATH" != "$EXPECTED_WORKTREE_ROOT" ]; then
  printf 'assigned-worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$GIT_WORKTREE_PATH" >&2
  exit 1
fi

if [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ] && [ "$GIT_WORKTREE_BRANCH_REF" != "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
  printf 'assigned-branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$GIT_WORKTREE_BRANCH_REF" >&2
  exit 1
fi

if [ -n "$EXPECTED_HEAD" ] && [ "$GIT_HEAD" != "$EXPECTED_HEAD" ]; then
  printf 'assigned-head mismatch: expected %s got %s\n' "$EXPECTED_HEAD" "$GIT_HEAD" >&2
  exit 1
fi

EXPECTED_WORKTREE_ROOT_RECORDED=""
EXPECTED_BRANCH_REF_RECORDED=""
RECORDED_BRANCH_REF_CANONICAL=""
EXPECTED_HEAD_RECORDED=""
LANE_VERIFY_COMMAND=""

if [ -n "$EXPECTED_WORKTREE_ROOT" ] || [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ] || [ -n "$EXPECTED_HEAD" ]; then
  EXPECTED_WORKTREE_ROOT_RECORDED="$(require_key "$REPORT_PATH" expected_worktree_root)"
  EXPECTED_BRANCH_REF_RECORDED="$(require_key "$REPORT_PATH" expected_branch_ref)"
  LANE_VERIFY_COMMAND="$(require_key "$REPORT_PATH" lane_verify_command)"

  if [ -n "$EXPECTED_WORKTREE_ROOT" ] && [ "$EXPECTED_WORKTREE_ROOT_RECORDED" != "$EXPECTED_WORKTREE_ROOT" ]; then
    printf 'report expected_worktree_root mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$EXPECTED_WORKTREE_ROOT_RECORDED" >&2
    exit 1
  fi

  if [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
    RECORDED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF_RECORDED")"
    if [ "$RECORDED_BRANCH_REF_CANONICAL" != "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
      printf 'report expected_branch_ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$RECORDED_BRANCH_REF_CANONICAL" >&2
      exit 1
    fi
  fi

  if [ -n "$EXPECTED_HEAD" ]; then
    EXPECTED_HEAD_RECORDED="$(require_key "$REPORT_PATH" expected_head)"
    if [ "$EXPECTED_HEAD_RECORDED" != "$EXPECTED_HEAD" ]; then
      printf 'report expected_head mismatch: expected %s got %s\n' "$EXPECTED_HEAD" "$EXPECTED_HEAD_RECORDED" >&2
      exit 1
    fi
  elif grep -q '^expected_head=' "$REPORT_PATH"; then
    EXPECTED_HEAD_RECORDED="$(require_key "$REPORT_PATH" expected_head)"
  fi

elif grep -q '^expected_worktree_root=' "$REPORT_PATH"; then
  EXPECTED_WORKTREE_ROOT_RECORDED="$(require_key "$REPORT_PATH" expected_worktree_root)"
fi

if [ -z "$EXPECTED_BRANCH_REF_RECORDED" ] && grep -q '^expected_branch_ref=' "$REPORT_PATH"; then
  EXPECTED_BRANCH_REF_RECORDED="$(require_key "$REPORT_PATH" expected_branch_ref)"
fi
if [ -n "$EXPECTED_BRANCH_REF_RECORDED" ]; then
  RECORDED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF_RECORDED")"
fi
if [ -z "$EXPECTED_HEAD_RECORDED" ] && grep -q '^expected_head=' "$REPORT_PATH"; then
  EXPECTED_HEAD_RECORDED="$(require_key "$REPORT_PATH" expected_head)"
fi
if [ -z "$LANE_VERIFY_COMMAND" ] && grep -q '^lane_verify_command=' "$REPORT_PATH"; then
  LANE_VERIFY_COMMAND="$(require_key "$REPORT_PATH" lane_verify_command)"
fi

if [ -n "$EXPECTED_WORKTREE_ROOT_RECORDED" ]; then
  case "$LANE_VERIFY_COMMAND" in
    *"--expected-worktree-root $EXPECTED_WORKTREE_ROOT_RECORDED"*) ;;
    *)
      printf 'lane_verify_command missing --expected-worktree-root %s in %s\n' "$EXPECTED_WORKTREE_ROOT_RECORDED" "$REPORT_PATH" >&2
      exit 1
      ;;
  esac
fi

if [ -n "$EXPECTED_BRANCH_REF_RECORDED" ]; then
  case "$LANE_VERIFY_COMMAND" in
    *"--expected-branch-ref $EXPECTED_BRANCH_REF_RECORDED"*) ;;
    *"--expected-branch-ref $RECORDED_BRANCH_REF_CANONICAL"*) ;;
    *)
      printf 'lane_verify_command missing --expected-branch-ref %s in %s\n' "$EXPECTED_BRANCH_REF_RECORDED" "$REPORT_PATH" >&2
      exit 1
      ;;
  esac
fi

if [ -n "$EXPECTED_HEAD_RECORDED" ]; then
  case "$LANE_VERIFY_COMMAND" in
    *"--expected-head $EXPECTED_HEAD_RECORDED"*) ;;
    *)
      printf 'lane_verify_command missing --expected-head %s in %s\n' "$EXPECTED_HEAD_RECORDED" "$REPORT_PATH" >&2
      exit 1
      ;;
  esac
fi

if [ -n "$EXPECTED_WORKTREE_ROOT_RECORDED" ] || [ -n "$EXPECTED_BRANCH_REF_RECORDED" ] || [ -n "$LANE_VERIFY_COMMAND" ]; then
  [ -n "$EXPECTED_WORKTREE_ROOT_RECORDED" ] || {
    printf 'incomplete lane binding in %s: missing expected_worktree_root\n' "$REPORT_PATH" >&2
    exit 1
  }
  [ -n "$EXPECTED_BRANCH_REF_RECORDED" ] || {
    printf 'incomplete lane binding in %s: missing expected_branch_ref\n' "$REPORT_PATH" >&2
    exit 1
  }
  [ -n "$LANE_VERIFY_COMMAND" ] || {
    printf 'incomplete lane binding in %s: missing lane_verify_command\n' "$REPORT_PATH" >&2
    exit 1
  }
fi

printf 'report_path=%s\n' "$REPORT_PATH"
printf 'dr_summary_path=%s\n' "$REPORT_PATH"
printf 'generated_at=%s\n' "$GENERATED_AT"
printf 'dr_generated_at=%s\n' "$GENERATED_AT"
printf 'config_path=%s\n' "$CONFIG_PATH"
printf 'git_worktree_path=%s\n' "$GIT_WORKTREE_PATH"
printf 'verified_worktree=%s\n' "$GIT_WORKTREE_PATH"
printf 'git_worktree_branch_ref=%s\n' "$GIT_WORKTREE_BRANCH_REF"
printf 'verified_branch_ref=%s\n' "$GIT_WORKTREE_BRANCH_REF"
printf 'git_branch=%s\n' "$GIT_BRANCH"
printf 'git_head=%s\n' "$GIT_HEAD"
printf 'verified_head=%s\n' "$GIT_HEAD"
printf 'git_status_summary=%s\n' "$GIT_STATUS_SUMMARY"
if [ -n "$EXPECTED_WORKTREE_ROOT_RECORDED" ]; then
  printf 'expected_worktree_root=%s\n' "$EXPECTED_WORKTREE_ROOT_RECORDED"
fi
if [ -n "$EXPECTED_BRANCH_REF_RECORDED" ]; then
  printf 'expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF_RECORDED"
fi
if [ -n "$EXPECTED_HEAD_RECORDED" ]; then
  printf 'expected_head=%s\n' "$EXPECTED_HEAD_RECORDED"
fi
if [ -n "$LANE_VERIFY_COMMAND" ]; then
  printf 'lane_verify_command=%s\n' "$LANE_VERIFY_COMMAND"
fi
printf 'rollback_command=%s\n' "$ROLLBACK_COMMAND"
printf 'dr_rollback_command=%s\n' "$ROLLBACK_COMMAND"
printf 'replay_command=%s\n' "$REPLAY_COMMAND"
printf 'dr_replay_command=%s\n' "$REPLAY_COMMAND"
printf 'status=%s\n' "$STATUS"
printf 'dr_status=%s\n' "$STATUS"
