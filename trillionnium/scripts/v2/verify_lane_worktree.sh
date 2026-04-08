#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF' >&2
Usage: verify_lane_worktree.sh --expected-worktree-root <absolute-path> --expected-branch-ref <ref> [--expected-head <sha>]

Fail-closed helper for lane/ticket-bound validator release rehearsals.
It verifies the current git worktree root, attached branch ref, and optional HEAD
against the supervisor-assigned values, then prints the resolved identity and the
matching `git worktree list --porcelain` stanza for artifact capture.
`--expected-worktree-root` must be an absolute path copied from the ticket/lane assignment.
`--expected-branch-ref` accepts either a full ref (for example
`refs/heads/lane/foo`) or a short branch name (for example `lane/foo`).
EOF
}

EXPECTED_WORKTREE_ROOT=""
EXPECTED_BRANCH_REF=""
EXPECTED_BRANCH_REF_CANONICAL=""
EXPECTED_HEAD=""

canonicalize_directory_path() {
  local path="$1"

  [ -d "$path" ] || {
    printf 'expected worktree root is not a directory: %s\n' "$path" >&2
    exit 2
  }

  (
    cd "$path"
    pwd -P
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

  case "$value" in
    /*) ;;
    *)
      printf 'invalid %s: expected absolute path got %s\n' "$flag_name" "$value" >&2
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

require_worktree_root_value --expected-worktree-root "$EXPECTED_WORKTREE_ROOT"
EXPECTED_WORKTREE_ROOT="$(canonicalize_directory_path "$EXPECTED_WORKTREE_ROOT")"
require_ref_token --expected-branch-ref "$EXPECTED_BRANCH_REF"
if [ -n "$EXPECTED_HEAD" ]; then
  require_ref_token --expected-head "$EXPECTED_HEAD"
  case "$EXPECTED_HEAD" in
    [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;;
    *)
      printf 'invalid --expected-head: expected 40-hex sha got %s\n' "$EXPECTED_HEAD" >&2
      exit 2
      ;;
  esac
fi

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

EXPECTED_BRANCH_REF_CANONICAL="$(canonicalize_branch_ref "$EXPECTED_BRANCH_REF")"
case "$EXPECTED_BRANCH_REF_CANONICAL" in
  refs/heads/*) ;;
  *)
    printf 'invalid --expected-branch-ref: expected refs/heads/* got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" >&2
    exit 2
    ;;
esac

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "not inside a git worktree" >&2
  exit 1
}

CURRENT_WORKTREE_ROOT="$(git rev-parse --show-toplevel)"
CURRENT_BRANCH_NAME="$(git branch --show-current)"
CURRENT_HEAD="$(git rev-parse HEAD)"

[ -n "$CURRENT_BRANCH_NAME" ] || {
  echo "detached HEAD: no branch checked out" >&2
  exit 1
}

CURRENT_BRANCH_REF="refs/heads/${CURRENT_BRANCH_NAME}"
CURRENT_WORKTREE_ENTRY="$(git worktree list --porcelain | awk -v target="$CURRENT_WORKTREE_ROOT" '
  BEGIN { in_match=0 }
  /^worktree / {
    worktree_path = substr($0, length("worktree ") + 1)
    in_match = (worktree_path == target)
  }
  in_match { print }
  in_match && /^$/ { exit }
')"
CURRENT_WORKTREE_ENTRY_BRANCH_REF="$(printf '%s\n' "$CURRENT_WORKTREE_ENTRY" | awk '/^branch / { print $2; exit }')"

[ "$CURRENT_WORKTREE_ROOT" = "$EXPECTED_WORKTREE_ROOT" ] || {
  printf 'worktree mismatch: expected %s got %s\n' "$EXPECTED_WORKTREE_ROOT" "$CURRENT_WORKTREE_ROOT" >&2
  exit 1
}

[ "$CURRENT_BRANCH_REF" = "$EXPECTED_BRANCH_REF_CANONICAL" ] || {
  printf 'branch-ref mismatch: expected %s got %s\n' "$EXPECTED_BRANCH_REF_CANONICAL" "$CURRENT_BRANCH_REF" >&2
  exit 1
}

if [ -n "$EXPECTED_HEAD" ] && [ "$CURRENT_HEAD" != "$EXPECTED_HEAD" ]; then
  printf 'head mismatch: expected %s got %s\n' "$EXPECTED_HEAD" "$CURRENT_HEAD" >&2
  exit 1
fi

[ -n "$CURRENT_WORKTREE_ENTRY" ] || {
  printf 'missing git worktree stanza for %s\n' "$CURRENT_WORKTREE_ROOT" >&2
  exit 1
}

[ -n "$CURRENT_WORKTREE_ENTRY_BRANCH_REF" ] || {
  printf 'missing git worktree branch binding for %s\n' "$CURRENT_WORKTREE_ROOT" >&2
  exit 1
}

[ "$CURRENT_WORKTREE_ENTRY_BRANCH_REF" = "$CURRENT_BRANCH_REF" ] || {
  printf 'worktree branch binding mismatch: expected %s got %s\n' "$CURRENT_BRANCH_REF" "$CURRENT_WORKTREE_ENTRY_BRANCH_REF" >&2
  exit 1
}

printf 'verified_worktree=%s\n' "$CURRENT_WORKTREE_ROOT"
printf 'verified_branch_ref=%s\n' "$CURRENT_BRANCH_REF"
printf 'verified_head=%s\n' "$CURRENT_HEAD"
printf '%s\n' "$CURRENT_WORKTREE_ENTRY"
