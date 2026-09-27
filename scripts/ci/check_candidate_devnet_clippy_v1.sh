#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
manifest="$root/trillionnium/Cargo.toml"
lockfile="$root/trillionnium/Cargo.lock"
package=trnm-poco-lab-validator

for path in \
  "$root/trillionnium/crates/trnm-poco-lab-validator/src/candidate_devnet.rs" \
  "$root/trillionnium/crates/trnm-poco-lab-validator/src/bin/trnm-poco-candidate-devnet-validator.rs" \
  "$root/trillionnium/crates/trnm-poco-lab-validator/tests/candidate_devnet_cli.rs" \
  "$manifest" \
  "$lockfile"; do
  test -f "$path"
done

# Lint the real workspace package under the repository lock.  The former
# synthetic harness generated a second unlocked dependency graph, so an
# offline job could request packages absent from the exact reviewed lock and
# mutate the shared runner cache before any candidate regression executed.
tmp_base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
target=$(mktemp -d "$tmp_base/trnm-candidate-devnet-clippy-target.XXXXXX")
cleanup() { rm -rf -- "$target"; }
trap cleanup EXIT
export CARGO_TARGET_DIR="$target"

cargo clippy \
  --manifest-path "$manifest" \
  -p "$package" \
  --all-targets \
  --locked \
  --offline \
  --no-deps \
  -- \
  -D warnings

git -C "$root" diff --exit-code -- "$lockfile"
test -z "$(git -C "$root" status --porcelain --untracked-files=all)"
printf "candidate_devnet_clippy=passed workspace_lock=exact dependency_lints=excluded\n"
