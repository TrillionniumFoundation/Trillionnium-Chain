#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: extract_release_handoff_fields.sh [--summary-path <path>] [--manifest-path <path>] [--expected-worktree-root <path>] [--expected-branch-ref <ref>]

Resolve the latest local-evidence summary and RC manifest (unless paths are
provided explicitly), then print the canonical handoff fields directly from the
artifacts. This is a fail-closed helper for validator/operator release handoff:
it refuses to guess missing paths or silently continue when identity fields
mismatch across artifacts. When expected lane identity is provided, the helper
also verifies the artifact worktree path and branch ref against the assigned
values before emitting the handoff block.
EOF
}

SUMMARY_PATH=""
MANIFEST_PATH=""
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_BRANCH_REF_CANONICAL=""

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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --summary-path)
      [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }
      SUMMARY_PATH="$2"
      shift 2
      ;;
    --manifest-path)
      [ "$#" -ge 2 ] || { echo "missing value for $1" >&2; usage; exit 2; }
      MANIFEST_PATH="$2"
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

if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  require_worktree_root_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
fi
if [ -n "$EXPECTED_BRANCH_REF" ]; then
  require_ref_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
  EXPECTED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")"
fi
if [ -n "$EXPECTED_WORKTREE_ROOT" ] && [ -z "$EXPECTED_BRANCH_REF" ]; then
  echo "missing --expected-branch-ref when --expected-worktree-root is provided" >&2
  usage
  exit 2
fi
if [ -n "$EXPECTED_BRANCH_REF" ] && [ -z "$EXPECTED_WORKTREE_ROOT" ]; then
  echo "missing --expected-worktree-root when --expected-branch-ref is provided" >&2
  usage
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel)"

if [ -z "$SUMMARY_PATH" ]; then
  latest_evidence_dir="$(find "$ROOT/run/health" -maxdepth 1 -type d -name 'evidence-*' -print 2>/dev/null | sort | tail -n 1)"
  [ -n "$latest_evidence_dir" ] || { echo "missing local evidence directory under $ROOT/run/health" >&2; exit 1; }
  SUMMARY_PATH="$latest_evidence_dir/summary.txt"
fi

if [ -z "$MANIFEST_PATH" ]; then
  latest_rc_dir="$(find "$ROOT/release" -maxdepth 1 -type d -name 'rc-*' -print 2>/dev/null | sort | tail -n 1)"
  [ -n "$latest_rc_dir" ] || { echo "missing rc manifest directory under $ROOT/release" >&2; exit 1; }
  MANIFEST_PATH="$latest_rc_dir/manifest.txt"
fi

[ -f "$SUMMARY_PATH" ] || { echo "missing summary file: $SUMMARY_PATH" >&2; exit 1; }
[ -f "$MANIFEST_PATH" ] || { echo "missing manifest file: $MANIFEST_PATH" >&2; exit 1; }

require_key() {
  local path="$1"
  local key="$2"
  local value
  value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path")"
  [ -n "$value" ] || { printf 'missing %s in %s\n' "$key" "$path" >&2; exit 1; }
  printf '%s' "$value"
}

assert_equal() {
  local field="$1"
  local left="$2"
  local right="$3"
  if [ "$left" != "$right" ]; then
    printf 'artifact mismatch for %s: summary=%s manifest=%s\n' "$field" "$left" "$right" >&2
    exit 1
  fi
}

summary_branch="$(require_key "$SUMMARY_PATH" git_branch)"
summary_head="$(require_key "$SUMMARY_PATH" git_head)"
summary_head_state="$(require_key "$SUMMARY_PATH" git_head_state)"
summary_worktree_path="$(require_key "$SUMMARY_PATH" git_worktree_path)"
summary_worktree_branch_ref="$(require_key "$SUMMARY_PATH" git_worktree_branch_ref)"
summary_truth_source="$(require_key "$SUMMARY_PATH" truth_source)"
summary_result="$(require_key "$SUMMARY_PATH" result)"
summary_rollback="$(require_key "$SUMMARY_PATH" rollback_command)"
summary_replay="$(require_key "$SUMMARY_PATH" replay_command)"

manifest_branch="$(require_key "$MANIFEST_PATH" git_branch)"
manifest_head="$(require_key "$MANIFEST_PATH" git_head)"
manifest_head_state="$(require_key "$MANIFEST_PATH" git_head_state)"
manifest_worktree_path="$(require_key "$MANIFEST_PATH" git_worktree_path)"
manifest_worktree_branch_ref="$(require_key "$MANIFEST_PATH" git_worktree_branch_ref)"
manifest_truth_source="$(require_key "$MANIFEST_PATH" truth_source)"
manifest_rollback="$(require_key "$MANIFEST_PATH" rollback_command)"
manifest_replay="$(require_key "$MANIFEST_PATH" replay_command)"

assert_equal git_branch "$summary_branch" "$manifest_branch"
assert_equal git_head "$summary_head" "$manifest_head"
assert_equal git_head_state "$summary_head_state" "$manifest_head_state"
assert_equal git_worktree_path "$summary_worktree_path" "$manifest_worktree_path"
assert_equal git_worktree_branch_ref "$summary_worktree_branch_ref" "$manifest_worktree_branch_ref"
assert_equal truth_source "$summary_truth_source" "$manifest_truth_source"
assert_equal rollback_command "$summary_rollback" "$manifest_rollback"
assert_equal replay_command "$summary_replay" "$manifest_replay"

if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  [ "$summary_worktree_path" = "$EXPECTED_WORKTREE_ROOT" ] || {
    printf 'expected worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$summary_worktree_path" >&2
    exit 1
  }
  [ "$manifest_worktree_path" = "$EXPECTED_WORKTREE_ROOT" ] || {
    printf 'expected worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$manifest_worktree_path" >&2
    exit 1
  }
  [ "$summary_worktree_branch_ref" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
    printf 'expected branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$summary_worktree_branch_ref" >&2
    exit 1
  }
  [ "$manifest_worktree_branch_ref" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
    printf 'expected branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$manifest_worktree_branch_ref" >&2
    exit 1
  }
fi

current_branch_ref="$(git symbolic-ref -q HEAD || true)"
if [ -n "$current_branch_ref" ]; then
  if [ "$current_branch_ref" = "$summary_worktree_branch_ref" ]; then
    git_worktree_branch_ref_match="true"
  else
    git_worktree_branch_ref_match="false"
  fi
else
  git_worktree_branch_ref_match="unknown"
fi

printf 'summary_path=%s\n' "$SUMMARY_PATH"
printf 'manifest_path=%s\n' "$MANIFEST_PATH"
if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  printf 'git_expected_worktree_path=%s\n' "$EXPECTED_WORKTREE_ROOT"
  printf 'git_expected_worktree_branch_ref=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL"
fi
printf 'git_branch=%s\n' "$summary_branch"
printf 'git_head=%s\n' "$summary_head"
printf 'git_head_state=%s\n' "$summary_head_state"
printf 'git_worktree_path=%s\n' "$summary_worktree_path"
printf 'git_worktree_branch_ref=%s\n' "$summary_worktree_branch_ref"
printf 'git_worktree_branch_ref_match=%s\n' "$git_worktree_branch_ref_match"
printf 'summary_truth_source=%s\n' "$summary_truth_source"
printf 'summary_result=%s\n' "$summary_result"
printf 'summary_rollback_command=%s\n' "$summary_rollback"
printf 'summary_replay_command=%s\n' "$summary_replay"
printf 'manifest_truth_source=%s\n' "$manifest_truth_source"
printf 'manifest_rollback_command=%s\n' "$manifest_rollback"
printf 'manifest_replay_command=%s\n' "$manifest_replay"
