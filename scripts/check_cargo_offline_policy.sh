#!/usr/bin/env bash
set -euo pipefail

source_mode=${1:---worktree}
case "$source_mode" in
  --worktree|--staged|--head) ;;
  *)
    echo "unsupported mixed-trust Cargo policy source: $source_mode" >&2
    exit 2
    ;;
esac

root=$(git rev-parse --show-toplevel)
root=$(cd "$root" && pwd -P)
baseline=.github/workflows/trnm-required-baseline.yml
privileged=scripts/check_privileged_cargo_offline_policy.sh
test -f "$root/$privileged" || {
  echo "mixed-trust Cargo policy: privileged policy is missing" >&2
  exit 2
}

# First validate the complete source in its original representation.
# This proves that the hosted required baseline and every privileged
# workflow remain present in their distinct trust classes.
bash "$root/scripts/check_ci_runner_policy.sh" "$source_mode"

tmp=$(mktemp -d)
cleanup_snapshot() {
  rm -rf -- "$tmp"
}
trap cleanup_snapshot EXIT HUP INT TERM

run_snapshot_policy() (
  # A snapshot is a foreign repository. Inherited hook variables such as
  # GIT_DIR and GIT_INDEX_FILE must not redirect its writes into the source.
  # Keep those variables intact for the earlier read of the selected source.
  local_environment=$(git -C "$root" rev-parse --local-env-vars)
  while IFS= read -r variable; do
    [[ "$variable" =~ ^GIT_[A-Z0-9_]+$ ]] || {
      echo "invalid repository-local Git environment name" >&2
      exit 2
    }
    unset "$variable"
  done <<<"$local_environment"
  git -C "$snapshot" init -q
  git -C "$snapshot" add -A
  env \
    GIT_AUTHOR_NAME=trnm-policy-snapshot \
    GIT_AUTHOR_EMAIL=policy-snapshot@example.invalid \
    GIT_COMMITTER_NAME=trnm-policy-snapshot \
    GIT_COMMITTER_EMAIL=policy-snapshot@example.invalid \
    git -C "$snapshot" commit -qm "${source_mode#--}-policy-snapshot"
  test ! -e "$snapshot/$baseline"
  cd "$snapshot"
  bash "./$privileged" --head
)

case "$source_mode" in
  --worktree)
    test -f "$root/$baseline" || {
      echo "mixed-trust Cargo policy: required hosted baseline is missing" >&2
      exit 2
    }
    # The privileged validator already filters hosted workflow names. Moving
    # this source file races other readers and loses it on uncatchable exit.
    bash "$root/$privileged" --worktree
    ;;
  --staged)
    snapshot="$tmp/snapshot"
    mkdir -p "$snapshot"
    git -C "$root" checkout-index --all --prefix="$snapshot/"
    rm -f "$snapshot/$baseline"
    run_snapshot_policy
    ;;
  --head)
    snapshot="$tmp/snapshot"
    mkdir -p "$snapshot"
    git -C "$root" archive --format=tar HEAD | tar -xf - -C "$snapshot"
    rm -f "$snapshot/$baseline"
    run_snapshot_policy
    ;;
esac

trap - EXIT HUP INT TERM
cleanup_snapshot
printf 'mixed_trust_cargo_policy=passed hosted_required_jobs=5 privileged_offline_jobs=26 source=%s\n' "${source_mode#--}"
