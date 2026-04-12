#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: extract_release_handoff_fields.sh [--summary-path <path>] [--manifest-path <path>]
                                         [--expected-worktree-root <path>] [--expected-branch-ref <ref>]
                                         [--expected-head <sha>]

Resolve the latest local-evidence summary and RC manifest (unless paths are
provided explicitly), then print the canonical handoff fields directly from the
artifacts. This is a fail-closed helper for validator/operator release handoff:
it refuses to guess missing paths or silently continue when identity fields
mismatch across artifacts.

When --expected-worktree-root / --expected-branch-ref are provided, the helper
also verifies that both artifacts match the ticket-assigned lane binding.
--expected-branch-ref accepts either a short branch name (for example
lane/foo) or a full ref (for example refs/heads/lane/foo). When
--expected-head is provided, the helper also fail-closes on head drift from
that ticket-assigned commit.
EOF
}

SUMMARY_PATH=""
MANIFEST_PATH=""
EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_BRANCH_REF_CANONICAL=""
EXPECTED_HEAD=""
VERIFIED_WORKTREE=""
VERIFIED_BRANCH_REF=""
VERIFIED_HEAD=""
PREFLIGHT_PATH=""
PREFLIGHT_SUMMARY_PATH=""

canonicalize_branch_ref() {
  local ref="$1"
  case "$ref" in
    refs/*) printf '%s' "$ref" ;;
    *) printf 'refs/heads/%s' "$ref" ;;
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
if [ -n "$EXPECTED_HEAD" ] && { [ -z "$EXPECTED_WORKTREE_ROOT" ] || [ -z "$EXPECTED_BRANCH_REF" ]; }; then
  echo "--expected-worktree-root and --expected-branch-ref are required when --expected-head is set" >&2
  usage
  exit 2
fi

if [ -n "$EXPECTED_BRANCH_REF" ]; then
  EXPECTED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")"
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TRNM_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
VERIFY_LANE_WORKTREE_HELPER="$SCRIPT_DIR/verify_lane_worktree.sh"

if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  [ -x "$VERIFY_LANE_WORKTREE_HELPER" ] || {
    printf 'missing verify helper: %s\n' "$VERIFY_LANE_WORKTREE_HELPER" >&2
    exit 1
  }

  verify_args=(
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
    --expected-branch-ref "$EXPECTED_BRANCH_REF"
  )
  if [ -n "$EXPECTED_HEAD" ]; then
    verify_args+=(--expected-head "$EXPECTED_HEAD")
  fi

  VERIFY_OUTPUT="$($VERIFY_LANE_WORKTREE_HELPER "${verify_args[@]}")"
  VERIFIED_WORKTREE="$(printf '%s\n' "$VERIFY_OUTPUT" | awk -F= '$1 == "verified_worktree" { print $2; exit }')"
  VERIFIED_BRANCH_REF="$(printf '%s\n' "$VERIFY_OUTPUT" | awk -F= '$1 == "verified_branch_ref" { print $2; exit }')"
  VERIFIED_HEAD="$(printf '%s\n' "$VERIFY_OUTPUT" | awk -F= '$1 == "verified_head" { print $2; exit }')"

  [ -n "$VERIFIED_WORKTREE" ] || { echo 'missing verified_worktree from verify helper' >&2; exit 1; }
  [ -n "$VERIFIED_BRANCH_REF" ] || { echo 'missing verified_branch_ref from verify helper' >&2; exit 1; }
  [ -n "$VERIFIED_HEAD" ] || { echo 'missing verified_head from verify helper' >&2; exit 1; }
fi

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

if [ -f "$TRNM_ROOT/run/preflight/go-no-go-latest.txt" ]; then
  PREFLIGHT_PATH="$TRNM_ROOT/run/preflight/go-no-go-latest.txt"
fi
latest_stamped_preflight=""
if compgen -G "$TRNM_ROOT/run/preflight/go-no-go-*.txt" >/dev/null; then
  latest_stamped_preflight="$(ls -dt "$TRNM_ROOT"/run/preflight/go-no-go-*.txt 2>/dev/null | awk '!/\/go-no-go-latest\.txt$/ { print; exit }')"
fi
if [ -n "$latest_stamped_preflight" ]; then
  PREFLIGHT_SUMMARY_PATH="$latest_stamped_preflight"
elif [ -n "$PREFLIGHT_PATH" ]; then
  PREFLIGHT_SUMMARY_PATH="$PREFLIGHT_PATH"
fi

[ -f "$SUMMARY_PATH" ] || { echo "missing summary file: $SUMMARY_PATH" >&2; exit 1; }
[ -f "$MANIFEST_PATH" ] || { echo "missing manifest file: $MANIFEST_PATH" >&2; exit 1; }

resolve_path() {
  local path="$1"
  python3 - "$path" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
}

require_path_within_trnm_root() {
  local field_name="$1"
  local path="$2"
  case "$path" in
    "$TRNM_ROOT"|"$TRNM_ROOT"/*) ;;
    *)
      printf '%s must resolve under %s: %s\n' "$field_name" "$TRNM_ROOT" "$path" >&2
      exit 1
      ;;
  esac
}

count_keys() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$path"
}

extract_unique_key() {
  local path="$1"
  local key="$2"
  local key_count
  key_count="$(count_keys "$path" "$key")"
  if [ "$key_count" -gt 1 ]; then
    printf 'duplicate %s in %s\n' "$key" "$path" >&2
    exit 1
  fi
  [ "$key_count" -eq 1 ] || return 0
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$path"
}

optional_key() {
  local path="$1"
  local key="$2"
  extract_unique_key "$path" "$key"
}

require_key() {
  local path="$1"
  local key="$2"
  local value
  value="$(extract_unique_key "$path" "$key")"
  [ -n "$value" ] || { printf 'missing %s in %s\n' "$key" "$path" >&2; exit 1; }
  printf '%s' "$value"
}

assert_same() {
  local field="$1"
  local left="$2"
  local right="$3"
  if [ "$left" != "$right" ]; then
    printf 'artifact mismatch for %s: summary=%s manifest=%s\n' "$field" "$left" "$right" >&2
    exit 1
  fi
}

SUMMARY_PATH="$(resolve_path "$SUMMARY_PATH")"
MANIFEST_PATH="$(resolve_path "$MANIFEST_PATH")"
require_path_within_trnm_root summary_path "$SUMMARY_PATH"
require_path_within_trnm_root manifest_path "$MANIFEST_PATH"
if [ "$SUMMARY_PATH" = "$MANIFEST_PATH" ]; then
  printf 'summary and manifest paths must be distinct artifacts: %s\n' "$SUMMARY_PATH" >&2
  exit 1
fi
if [ -n "$PREFLIGHT_PATH" ]; then
  PREFLIGHT_PATH="$(resolve_path "$PREFLIGHT_PATH")"
  require_path_within_trnm_root preflight_path "$PREFLIGHT_PATH"
fi
if [ -n "$PREFLIGHT_SUMMARY_PATH" ]; then
  PREFLIGHT_SUMMARY_PATH="$(resolve_path "$PREFLIGHT_SUMMARY_PATH")"
  require_path_within_trnm_root preflight_summary_path "$PREFLIGHT_SUMMARY_PATH"
  if [ "$PREFLIGHT_SUMMARY_PATH" = "$SUMMARY_PATH" ] || [ "$PREFLIGHT_SUMMARY_PATH" = "$MANIFEST_PATH" ]; then
    printf 'preflight summary path must be distinct from summary/manifest artifacts: %s\n' "$PREFLIGHT_SUMMARY_PATH" >&2
    exit 1
  fi
fi

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

assert_same git_toplevel "$summary_toplevel" "$manifest_toplevel"
assert_same git_branch "$summary_branch" "$manifest_branch"
assert_same git_head "$summary_head" "$manifest_head"
assert_same git_head_state "$summary_head_state" "$manifest_head_state"
assert_same git_worktree_path "$summary_worktree_path" "$manifest_worktree_path"
assert_same git_worktree_branch_ref "$summary_worktree_branch_ref" "$manifest_worktree_branch_ref"
assert_same git_expected_worktree_branch_ref "$summary_expected_worktree_branch_ref" "$manifest_expected_worktree_branch_ref"
assert_same git_worktree_branch_ref_match "$summary_worktree_branch_ref_match" "$manifest_worktree_branch_ref_match"
assert_same git_status_summary "$summary_git_status_summary" "$manifest_git_status_summary"
assert_same truth_source "$summary_truth_source" "$manifest_truth_source"
assert_same historical_evidence_only "$summary_historical_evidence_only" "$manifest_historical_evidence_only"
assert_same evidence_scope "$summary_evidence_scope" "$manifest_evidence_scope"

[ "$summary_worktree_branch_ref_match" = "true" ] || {
  printf 'git_worktree_branch_ref_match must be true, got %s\n' "$summary_worktree_branch_ref_match" >&2
  exit 1
}

preflight_result=""
preflight_generated_at=""
preflight_toplevel=""
preflight_branch=""
preflight_head=""
preflight_head_state=""
preflight_git_status_summary=""
preflight_worktree_path=""
preflight_worktree_branch_ref=""
preflight_expected_worktree_branch_ref=""
preflight_worktree_branch_ref_match=""
preflight_expected_worktree_root=""
preflight_expected_branch_ref=""
preflight_expected_head=""
preflight_rollback=""
preflight_replay=""

if [ -n "$PREFLIGHT_SUMMARY_PATH" ]; then
  preflight_result="$(require_key "$PREFLIGHT_SUMMARY_PATH" result)"
  preflight_generated_at="$(require_key "$PREFLIGHT_SUMMARY_PATH" generated_at)"
  preflight_git_status_summary="$(require_key "$PREFLIGHT_SUMMARY_PATH" git_status_summary)"
  preflight_worktree_path="$(require_key "$PREFLIGHT_SUMMARY_PATH" git_worktree_path)"
  preflight_worktree_branch_ref="$(require_key "$PREFLIGHT_SUMMARY_PATH" git_worktree_branch_ref)"
  preflight_worktree_branch_ref_match="$(require_key "$PREFLIGHT_SUMMARY_PATH" git_worktree_branch_ref_match)"
  preflight_rollback="$(require_key "$PREFLIGHT_SUMMARY_PATH" rollback_command)"
  preflight_replay="$(require_key "$PREFLIGHT_SUMMARY_PATH" replay_command)"

  preflight_toplevel="$(optional_key "$PREFLIGHT_SUMMARY_PATH" git_toplevel)"
  preflight_branch="$(optional_key "$PREFLIGHT_SUMMARY_PATH" git_branch)"
  preflight_head="$(optional_key "$PREFLIGHT_SUMMARY_PATH" git_head)"
  preflight_head_state="$(optional_key "$PREFLIGHT_SUMMARY_PATH" git_head_state)"
  preflight_expected_worktree_branch_ref="$(optional_key "$PREFLIGHT_SUMMARY_PATH" git_expected_worktree_branch_ref)"
  preflight_expected_worktree_root="$(optional_key "$PREFLIGHT_SUMMARY_PATH" expected_worktree_root)"
  preflight_expected_branch_ref="$(optional_key "$PREFLIGHT_SUMMARY_PATH" expected_branch_ref)"
  preflight_expected_head="$(optional_key "$PREFLIGHT_SUMMARY_PATH" expected_head)"

  [ "$preflight_result" = "PASS" ] || {
    printf 'artifact mismatch for preflight result: expected PASS got %s\n' "$preflight_result" >&2
    exit 1
  }
  [ "$preflight_git_status_summary" = "clean" ] || {
    printf 'artifact mismatch for preflight git_status_summary: expected clean got %s\n' "$preflight_git_status_summary" >&2
    exit 1
  }
  [ "$preflight_worktree_path" = "$summary_worktree_path" ] || {
    printf 'artifact mismatch for preflight git_worktree_path: preflight=%s summary=%s\n' "$preflight_worktree_path" "$summary_worktree_path" >&2
    exit 1
  }
  [ "$preflight_worktree_branch_ref" = "$summary_worktree_branch_ref" ] || {
    printf 'artifact mismatch for preflight git_worktree_branch_ref: preflight=%s summary=%s\n' "$preflight_worktree_branch_ref" "$summary_worktree_branch_ref" >&2
    exit 1
  }
  [ "$preflight_worktree_branch_ref_match" = "true" ] || {
    printf 'artifact mismatch for preflight git_worktree_branch_ref_match: expected true got %s\n' "$preflight_worktree_branch_ref_match" >&2
    exit 1
  }

  if [ -n "$preflight_toplevel" ]; then
    [ "$preflight_toplevel" = "$summary_toplevel" ] || { printf 'preflight artifact mismatch for git_toplevel: preflight=%s summary=%s\n' "$preflight_toplevel" "$summary_toplevel" >&2; exit 1; }
  fi
  if [ -n "$preflight_branch" ]; then
    [ "$preflight_branch" = "$summary_branch" ] || { printf 'preflight artifact mismatch for git_branch: preflight=%s summary=%s\n' "$preflight_branch" "$summary_branch" >&2; exit 1; }
  fi
  if [ -n "$preflight_head" ]; then
    [ "$preflight_head" = "$summary_head" ] || { printf 'preflight artifact mismatch for git_head: preflight=%s summary=%s\n' "$preflight_head" "$summary_head" >&2; exit 1; }
  fi
  if [ -n "$preflight_head_state" ]; then
    [ "$preflight_head_state" = "$summary_head_state" ] || { printf 'preflight artifact mismatch for git_head_state: preflight=%s summary=%s\n' "$preflight_head_state" "$summary_head_state" >&2; exit 1; }
  fi
  if [ -n "$preflight_expected_worktree_branch_ref" ]; then
    [ "$preflight_expected_worktree_branch_ref" = "$summary_expected_worktree_branch_ref" ] || { printf 'preflight artifact mismatch for expected branch ref: preflight=%s summary=%s\n' "$preflight_expected_worktree_branch_ref" "$summary_expected_worktree_branch_ref" >&2; exit 1; }
  fi
fi

if [ -n "$EXPECTED_WORKTREE_ROOT" ]; then
  [ "$summary_worktree_path" = "$EXPECTED_WORKTREE_ROOT" ] || {
    printf 'artifact mismatch for expected worktree root: expected=%s summary=%s\n' "$EXPECTED_WORKTREE_ROOT" "$summary_worktree_path" >&2
    exit 1
  }
  [ "$summary_expected_worktree_branch_ref" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
    printf 'artifact mismatch for artifact expected branch ref: expected=%s summary=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$summary_expected_worktree_branch_ref" >&2
    exit 1
  }
  [ "$summary_worktree_branch_ref" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
    printf 'artifact mismatch for expected branch ref: expected=%s summary=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$summary_worktree_branch_ref" >&2
    exit 1
  }
fi

if [ -n "$EXPECTED_HEAD" ]; then
  [ "$summary_head" = "$EXPECTED_HEAD" ] || {
    printf 'head mismatch: expected %s got %s\n' "$EXPECTED_HEAD" "$summary_head" >&2
    exit 1
  }
fi

if [ -n "$VERIFIED_WORKTREE" ] && [ "$summary_worktree_path" != "$VERIFIED_WORKTREE" ]; then
  printf 'artifact mismatch for verified worktree: verified=%s summary=%s\n' "$VERIFIED_WORKTREE" "$summary_worktree_path" >&2
  exit 1
fi
if [ -n "$VERIFIED_BRANCH_REF" ] && [ "$summary_worktree_branch_ref" != "$VERIFIED_BRANCH_REF" ]; then
  printf 'artifact mismatch for verified branch ref: verified=%s summary=%s\n' "$VERIFIED_BRANCH_REF" "$summary_worktree_branch_ref" >&2
  exit 1
fi
if [ -n "$VERIFIED_BRANCH_REF" ] && [ "$summary_expected_worktree_branch_ref" != "$VERIFIED_BRANCH_REF" ]; then
  printf 'artifact mismatch for artifact expected branch ref vs verified branch ref: verified=%s summary=%s\n' "$VERIFIED_BRANCH_REF" "$summary_expected_worktree_branch_ref" >&2
  exit 1
fi
if [ -n "$VERIFIED_HEAD" ] && [ "$summary_head" != "$VERIFIED_HEAD" ]; then
  printf 'artifact mismatch for verified head: verified=%s summary=%s\n' "$VERIFIED_HEAD" "$summary_head" >&2
  exit 1
fi

if [ -n "$PREFLIGHT_SUMMARY_PATH" ]; then
  if [ -n "$VERIFIED_WORKTREE" ] && [ "$preflight_worktree_path" != "$VERIFIED_WORKTREE" ]; then
    printf 'preflight artifact mismatch for verified worktree: verified=%s preflight=%s\n' "$VERIFIED_WORKTREE" "$preflight_worktree_path" >&2
    exit 1
  fi
  if [ -n "$VERIFIED_BRANCH_REF" ] && [ "$preflight_worktree_branch_ref" != "$VERIFIED_BRANCH_REF" ]; then
    printf 'preflight artifact mismatch for verified branch ref: verified=%s preflight=%s\n' "$VERIFIED_BRANCH_REF" "$preflight_worktree_branch_ref" >&2
    exit 1
  fi
  if [ -n "$VERIFIED_HEAD" ] && [ -n "$preflight_head" ] && [ "$preflight_head" != "$VERIFIED_HEAD" ]; then
    printf 'preflight artifact mismatch for verified head: verified=%s preflight=%s\n' "$VERIFIED_HEAD" "$preflight_head" >&2
    exit 1
  fi
  if [ -n "$EXPECTED_WORKTREE_ROOT" ] && [ -n "$preflight_expected_worktree_root" ] && [ "$preflight_expected_worktree_root" != "$EXPECTED_WORKTREE_ROOT" ]; then
    printf 'preflight expected_worktree_root mismatch: expected=%s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$preflight_expected_worktree_root" >&2
    exit 1
  fi
  if [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ] && [ -n "$preflight_expected_branch_ref" ] && [ "$preflight_expected_branch_ref" != "$EXPECTED_BRANCH_REF_CANONICAL" ]; then
    printf 'preflight expected branch-ref mismatch: expected=%s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$preflight_expected_branch_ref" >&2
    exit 1
  fi
  if [ -n "$EXPECTED_HEAD" ] && [ -n "$preflight_expected_head" ] && [ "$preflight_expected_head" != "$EXPECTED_HEAD" ]; then
    printf 'preflight expected head mismatch: expected=%s got %s\n' "$EXPECTED_HEAD" "$preflight_expected_head" >&2
    exit 1
  fi
fi

if [ -n "$VERIFIED_WORKTREE" ]; then printf 'verified_worktree=%s\n' "$VERIFIED_WORKTREE"; fi
if [ -n "$VERIFIED_BRANCH_REF" ]; then printf 'verified_branch_ref=%s\n' "$VERIFIED_BRANCH_REF"; fi
if [ -n "$VERIFIED_HEAD" ]; then printf 'verified_head=%s\n' "$VERIFIED_HEAD"; fi

if [ -n "$PREFLIGHT_PATH" ]; then
  printf 'preflight_path=%s\n' "$PREFLIGHT_PATH"
else
  printf 'preflight_path=%s\n' '<missing>'
fi
if [ -n "$PREFLIGHT_SUMMARY_PATH" ]; then
  printf 'preflight_summary_path=%s\n' "$PREFLIGHT_SUMMARY_PATH"
  printf 'preflight_result=%s\n' "$preflight_result"
  printf 'preflight_generated_at=%s\n' "$preflight_generated_at"
  printf 'preflight_git_status_summary=%s\n' "$preflight_git_status_summary"
  printf 'preflight_git_worktree_path=%s\n' "$preflight_worktree_path"
  printf 'preflight_git_worktree_branch_ref=%s\n' "$preflight_worktree_branch_ref"
  printf 'preflight_git_worktree_branch_ref_match=%s\n' "$preflight_worktree_branch_ref_match"
  printf 'preflight_rollback_command=%s\n' "$preflight_rollback"
  printf 'preflight_replay_command=%s\n' "$preflight_replay"
  if [ -n "$preflight_toplevel" ]; then printf 'preflight_git_toplevel=%s\n' "$preflight_toplevel"; fi
  if [ -n "$preflight_branch" ]; then printf 'preflight_git_branch=%s\n' "$preflight_branch"; fi
  if [ -n "$preflight_head" ]; then printf 'preflight_git_head=%s\n' "$preflight_head"; fi
  if [ -n "$preflight_head_state" ]; then printf 'preflight_git_head_state=%s\n' "$preflight_head_state"; fi
  if [ -n "$preflight_expected_worktree_root" ]; then printf 'preflight_expected_worktree_root=%s\n' "$preflight_expected_worktree_root"; fi
  if [ -n "$EXPECTED_BRANCH_REF" ]; then printf 'preflight_ticket_expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF"; else printf 'preflight_ticket_expected_branch_ref=%s\n' '<unset>'; fi
  if [ -n "$preflight_expected_branch_ref" ]; then printf 'preflight_expected_branch_ref=%s\n' "$preflight_expected_branch_ref"; fi
  if [ -n "$preflight_expected_head" ]; then printf 'preflight_expected_head=%s\n' "$preflight_expected_head"; fi
else
  printf 'preflight_summary_path=%s\n' '<missing>'
fi

printf 'summary_path=%s\n' "$SUMMARY_PATH"
printf 'manifest_path=%s\n' "$MANIFEST_PATH"
if [ -n "$EXPECTED_BRANCH_REF" ]; then printf 'ticket_expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF"; else printf 'ticket_expected_branch_ref=%s\n' '<unset>'; fi
if [ -n "$EXPECTED_BRANCH_REF_CANONICAL" ]; then printf 'expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF_CANONICAL"; else printf 'expected_branch_ref=%s\n' '<unset>'; fi
if [ -n "$EXPECTED_HEAD" ]; then printf 'expected_head=%s\n' "$EXPECTED_HEAD"; else printf 'expected_head=%s\n' '<unset>'; fi
printf 'git_toplevel=%s\n' "$summary_toplevel"
printf 'git_branch=%s\n' "$summary_branch"
printf 'git_head=%s\n' "$summary_head"
printf 'git_head_state=%s\n' "$summary_head_state"
printf 'git_worktree_path=%s\n' "$summary_worktree_path"
printf 'git_worktree_branch_ref=%s\n' "$summary_worktree_branch_ref"
printf 'git_expected_worktree_branch_ref=%s\n' "$summary_expected_worktree_branch_ref"
printf 'git_worktree_branch_ref_match=%s\n' "$summary_worktree_branch_ref_match"
printf 'git_status_summary=%s\n' "$summary_git_status_summary"
printf 'generated_at=%s\n' "$summary_generated_at"
printf 'truth_source=%s\n' "$summary_truth_source"
printf 'historical_evidence_only=%s\n' "$summary_historical_evidence_only"
printf 'evidence_scope=%s\n' "$summary_evidence_scope"
printf 'result=%s\n' "$summary_result"
printf 'summary_rollback_command=%s\n' "$summary_rollback"
printf 'summary_replay_command=%s\n' "$summary_replay"
printf 'manifest_rollback_command=%s\n' "$manifest_rollback"
printf 'manifest_replay_command=%s\n' "$manifest_replay"
printf 'challenge_reexec_entry=%s\n' "$summary_challenge_reexec_entry"
printf 'replay_env_trnm_challenge_reexec_entry=%s\n' "$summary_replay_env_trnm_challenge_reexec_entry"
