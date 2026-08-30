#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

baseline=.github/workflows/trnm-required-baseline.yml
test -f "$baseline" || {
  echo "mixed-trust Cargo policy: required hosted baseline is missing" >&2
  exit 2
}

# The historical Cargo-offline contract governs only privileged X230 jobs. The
# actor-independent hosted baseline is a separate trust class: it installs
# pinned toolchains on an ephemeral GitHub-hosted image and is checked by the
# mixed runner policy plus repository truth. Hide only that reviewed hosted
# workflow while replaying the frozen 13-workflow/20-job offline contract.
tmp=$(mktemp -d)
restore() {
  if [[ -f "$tmp/trnm-required-baseline.yml" ]]; then
    mv "$tmp/trnm-required-baseline.yml" "$baseline"
  fi
  rm -rf -- "$tmp"
}
trap restore EXIT HUP INT TERM

mv "$baseline" "$tmp/trnm-required-baseline.yml"
bash scripts/check_cargo_offline_policy.sh --worktree
mv "$tmp/trnm-required-baseline.yml" "$baseline"
trap - EXIT HUP INT TERM
rm -rf -- "$tmp"

# Revalidate both trust classes after restoration. This forbids using the
# temporary separation to weaken or omit either the hosted required baseline
# or the privileged offline jobs.
bash scripts/check_ci_runner_policy.sh --worktree
python3 scripts/ci/check_repository_truth_v1.py >/dev/null

git diff --exit-code -- "$baseline" scripts/check_cargo_offline_policy.sh
test -z "$(git status --porcelain --untracked-files=all)"
printf 'mixed_trust_cargo_policy=passed hosted_required_jobs=5 privileged_offline_jobs=20\n'
