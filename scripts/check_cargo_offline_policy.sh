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
restore_worktree() {
  if [[ -f "$tmp/trnm-required-baseline.yml" ]]; then
    mv "$tmp/trnm-required-baseline.yml" "$root/$baseline"
  fi
  rm -rf -- "$tmp"
}
trap restore_worktree EXIT HUP INT TERM

case "$source_mode" in
  --worktree)
    test -f "$root/$baseline" || {
      echo "mixed-trust Cargo policy: required hosted baseline is missing" >&2
      exit 2
    }
    mv "$root/$baseline" "$tmp/trnm-required-baseline.yml"
    bash "$root/$privileged" --worktree
    mv "$tmp/trnm-required-baseline.yml" "$root/$baseline"
    ;;
  --staged)
    snapshot="$tmp/snapshot"
    mkdir -p "$snapshot"
    git -C "$root" checkout-index --all --prefix="$snapshot/"
    rm -f "$snapshot/$baseline"
    git -C "$snapshot" init -q
    git -C "$snapshot" add -A
    env \
      GIT_AUTHOR_NAME=trnm-policy-snapshot \
      GIT_AUTHOR_EMAIL=policy-snapshot@example.invalid \
      GIT_COMMITTER_NAME=trnm-policy-snapshot \
      GIT_COMMITTER_EMAIL=policy-snapshot@example.invalid \
      git -C "$snapshot" commit -qm staged-policy-snapshot
    test ! -e "$snapshot/$baseline"
    (cd "$snapshot" && bash "./$privileged" --head)
    ;;
  --head)
    snapshot="$tmp/snapshot"
    mkdir -p "$snapshot"
    git -C "$root" archive --format=tar HEAD | tar -xf - -C "$snapshot"
    rm -f "$snapshot/$baseline"
    git -C "$snapshot" init -q
    git -C "$snapshot" add -A
    env \
      GIT_AUTHOR_NAME=trnm-policy-snapshot \
      GIT_AUTHOR_EMAIL=policy-snapshot@example.invalid \
      GIT_COMMITTER_NAME=trnm-policy-snapshot \
      GIT_COMMITTER_EMAIL=policy-snapshot@example.invalid \
      git -C "$snapshot" commit -qm head-policy-snapshot
    test ! -e "$snapshot/$baseline"
    (cd "$snapshot" && bash "./$privileged" --head)
    ;;
esac

trap - EXIT HUP INT TERM
restore_worktree
printf 'mixed_trust_cargo_policy=passed hosted_required_jobs=5 privileged_offline_jobs=22 source=%s\n' "${source_mode#--}"
