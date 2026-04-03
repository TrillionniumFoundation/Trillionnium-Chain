#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: extract_release_handoff_fields.sh [--summary-path <path>] [--manifest-path <path>]
                                         [--expected-worktree-root <path>] [--expected-branch-ref <ref>]

Resolve the latest local-evidence summary and RC manifest (unless paths are
provided explicitly), then print the canonical handoff fields directly from the
artifacts. This is a fail-closed helper for validator/operator release handoff:
it refuses to guess missing paths or silently continue when identity fields
mismatch across artifacts.

When --expected-worktree-root / --expected-branch-ref are provided, the helper
also verifies that both artifacts match the ticket-assigned lane binding.
--expected-branch-ref accepts either a short branch name (for example
lane/foo) or a full ref (for example refs/heads/lane/foo).
EOF
}

SUMMARY_PATH=""
MANIFEST_PATH=""
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_BRANCH_REF_CANONICAL=""

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

if [ -n "$EXPECTED_WORKTREE_ROOT" ] && [ -z "$EXPECTED_BRANCH_REF" ]; then
  echo "--expected-branch-ref is required when --expected-worktree-root is set" >&2
  usage
  exit 2
fi

if [ -n "$EXPECTED_BRANCH_REF" ] && [ -z "$EXPECTED_WORKTREE_ROOT" ]; then
  echo "--expected-worktree-root is required when --expected-branch-ref is set" >&2
  usage
  exit 2
fi

if [ -n "$EXPECTED_BRANCH_REF" ]; then
  EXPECTED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")"
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TRNM_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"

if [ -z "$SUMMARY_PATH" ]; then
  latest_evidence_dir="$(ls -dt "$TRNM_ROOT"/run/health/evidence-* 2>/dev/null | head -n 1)"
  [ -n "$latest_evidence_dir" ] || { echo "missing local evidence directory under $TRNM_ROOT/run/health" >&2; exit 1; }
  SUMMARY_PATH="$latest_evidence_dir/summary.txt"
fi

if [ -z "$MANIFEST_PATH" ]; then
  latest_rc_dir="$(ls -dt "$TRNM_ROOT"/release/rc-* 2>/dev/null | head -n 1)"
  [ -n "$latest_rc_dir" ] || { echo "missing rc manifest directory under $TRNM_ROOT/release" >&2; exit 1; }
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

summary_toplevel="$(require_key "$SUMMARY_PATH" git_toplevel)"
summary_branch="$(require_key "$SUMMARY_PATH" git_branch)"
summary_head="$(require_key "$SUMMARY_PATH" git_head)"
summary_head_state="$(require_key "$SUMMARY_PATH" git_head_state)"
summary_worktree_path="$(require_key "$SUMMARY_PATH" git_worktree_path)"
summary_worktree_branch_ref="$(require_key "$SUMMARY_PATH" git_worktree_branch_ref)"
summary_expected_worktree_branch_ref="$(require_key "$SUMMARY_PATH" git_expected_worktree_branch_ref)"
summary_worktree_branch_ref_match="$(require_key "$SUMMARY_PATH" git_worktree_branch_ref_match)"
summary_git_status_summary="$(require_key "$SUMMARY_PATH" git_status_summary)"
summary_generated_at="$(require_key "$SUMMARY_PATH" generated_at)"
summary_truth_source="$(require_key "$SUMMARY_PATH" truth_source)"
summary_historical_evidence_only="$(require_key "$SUMMARY_PATH" historical_evidence_only)"
summary_evidence_scope="$(require_key "$SUMMARY_PATH" evidence_scope)"
summary_result="$(require_key "$SUMMARY_PATH" result)"
summary_rollback="$(require_key "$SUMMARY_PATH" rollback_command)"
summary_replay="$(require_key "$SUMMARY_PATH" replay_command)"
summary_challenge_reexec_entry="$(require_key "$SUMMARY_PATH" challenge_reexec_entry)"
summary_replay_env_trnm_challenge_reexec_entry="$(require_key "$SUMMARY_PATH" replay_env_trnm_challenge_reexec_entry)"

manifest_toplevel="$(require_key "$MANIFEST_PATH" git_toplevel)"
manifest_branch="$(require_key "$MANIFEST_PATH" git_branch)"
manifest_head="$(require_key "$MANIFEST_PATH" git_head)"
manifest_head_state="$(require_key "$MANIFEST_PATH" git_head_state)"
manifest_worktree_path="$(require_key "$MANIFEST_PATH" git_worktree_path)"
manifest_worktree_branch_ref="$(require_key "$MANIFEST_PATH" git_worktree_branch_ref)"
manifest_expected_worktree_branch_ref="$(require_key "$MANIFEST_PATH" git_expected_worktree_branch_ref)"
manifest_worktree_branch_ref_match="$(require_key "$MANIFEST_PATH" git_worktree_branch_ref_match)"
manifest_git_status_summary="$(require_key "$MANIFEST_PATH" git_status_summary)"
manifest_generated_at="$(require_key "$MANIFEST_PATH" generated_at)"
manifest_truth_source="$(require_key "$MANIFEST_PATH" truth_source)"
manifest_historical_evidence_only="$(require_key "$MANIFEST_PATH" historical_evidence_only)"
manifest_evidence_scope="$(require_key "$MANIFEST_PATH" evidence_scope)"
manifest_rollback="$(require_key "$MANIFEST_PATH" rollback_command)"
manifest_replay="$(require_key "$MANIFEST_PATH" replay_command)"

assert_equal git_toplevel "$summary_toplevel" "$manifest_toplevel"
assert_equal git_branch "$summary_branch" "$manifest_branch"
assert_equal git_head "$summary_head" "$manifest_head"
assert_equal git_head_state "$summary_head_state" "$manifest_head_state"
assert_equal git_worktree_path "$summary_worktree_path" "$manifest_worktree_path"
assert_equal git_worktree_branch_ref "$summary_worktree_branch_ref" "$manifest_worktree_branch_ref"
assert_equal git_expected_worktree_branch_ref "$summary_expected_worktree_branch_ref" "$manifest_expected_worktree_branch_ref"
assert_equal git_worktree_branch_ref_match "$summary_worktree_branch_ref_match" "$manifest_worktree_branch_ref_match"
assert_equal git_status_summary "$summary_git_status_summary" "$manifest_git_status_summary"
assert_equal truth_source "$summary_truth_source" "$manifest_truth_source"
assert_equal historical_evidence_only "$summary_historical_evidence_only" "$manifest_historical_evidence_only"
assert_equal evidence_scope "$summary_evidence_scope" "$manifest_evidence_scope"

if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  [ "$summary_worktree_path" = "$EXPECTED_WORKTREE_ROOT" ] || {
    printf 'artifact mismatch for expected worktree root: expected=%s summary=%s\n' "$EXPECTED_WORKTREE_ROOT" "$summary_worktree_path" >&2
    exit 1
  }
  [ "$summary_worktree_branch_ref" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
    printf 'artifact mismatch for expected branch ref: expected=%s summary=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$summary_worktree_branch_ref" >&2
    exit 1
  }
  [ "$summary_expected_worktree_branch_ref" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
    printf 'artifact mismatch for expected artifact branch ref: expected=%s summary=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$summary_expected_worktree_branch_ref" >&2
    exit 1
  }
fi

[ "$summary_worktree_branch_ref_match" = "true" ] || {
  printf 'git_worktree_branch_ref_match must be true, got %s\n' "$summary_worktree_branch_ref_match" >&2
  exit 1
}

if [ -n "$EXPECTED_WORKTREE_ROOT" ] && [ "$summary_worktree_path" != "$EXPECTED_WORKTREE_ROOT" ]; then
  printf 'assigned-worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$summary_worktree_path" >&2
  exit 1
fi

if [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ] && [ "$summary_worktree_branch_ref" != "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
  printf 'assigned-branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$summary_worktree_branch_ref" >&2
  exit 1
fi

printf 'summary_path=%s\n' "$SUMMARY_PATH"
printf 'manifest_path=%s\n' "$MANIFEST_PATH"
printf 'summary_generated_at=%s\n' "$summary_generated_at"
printf 'manifest_generated_at=%s\n' "$manifest_generated_at"
printf 'git_toplevel=%s\n' "$summary_toplevel"
printf 'git_branch=%s\n' "$summary_branch"
printf 'git_head=%s\n' "$summary_head"
printf 'git_head_state=%s\n' "$summary_head_state"
printf 'git_worktree_path=%s\n' "$summary_worktree_path"
printf 'git_worktree_branch_ref=%s\n' "$summary_worktree_branch_ref"
printf 'git_expected_worktree_branch_ref=%s\n' "$summary_expected_worktree_branch_ref"
printf 'git_worktree_branch_ref_match=%s\n' "$summary_worktree_branch_ref_match"
printf 'git_status_summary=%s\n' "$summary_git_status_summary"
printf 'truth_source=%s\n' "$summary_truth_source"
printf 'historical_evidence_only=%s\n' "$summary_historical_evidence_only"
printf 'evidence_scope=%s\n' "$summary_evidence_scope"
printf 'summary_result=%s\n' "$summary_result"
printf 'summary_rollback_command=%s\n' "$summary_rollback"
printf 'summary_replay_command=%s\n' "$summary_replay"
printf 'challenge_reexec_entry=%s\n' "$summary_challenge_reexec_entry"
printf 'replay_env_trnm_challenge_reexec_entry=%s\n' "$summary_replay_env_trnm_challenge_reexec_entry"
printf 'manifest_rollback_command=%s\n' "$manifest_rollback"
printf 'manifest_replay_command=%s\n' "$manifest_replay"

if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  printf 'expected_worktree_root=%s\n' "$EXPECTED_WORKTREE_ROOT"
  printf 'ticket_expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF"
  printf 'expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL"
fi
