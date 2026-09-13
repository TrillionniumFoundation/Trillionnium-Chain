#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

# The conformance campaign refreshes a tracked review report. Exact-head CI
# must leave the checkout byte-clean before the repository boundary audit, so
# preserve and restore that report on every success/failure path. PROJECT_TOPIC
# is Git-local developer metadata and may survive a reused self-hosted runner;
# it is never package evidence and must not influence a detached exact-head run.
report=docs/evidence/g2f/G2F_CONFORMANCE_RUN_V1.json
backup=$(mktemp)
jmt_binary=$(mktemp)
report_existed=false
if [[ -f "$report" ]]; then
  cp -- "$report" "$backup"
  report_existed=true
fi
topic_path=$(git rev-parse --path-format=absolute --git-path PROJECT_TOPIC)
rm -f -- "$topic_path"

restore_generated_state() {
  if [[ -f "$backup" ]]; then
    if [[ "$report_existed" == true ]]; then
      cp -- "$backup" "$report"
    else
      rm -f -- "$report"
    fi
    rm -f -- "$backup"
  fi
  rm -f -- "$jmt_binary" "$topic_path"
}
trap 'status=$?; restore_generated_state; exit "$status"' EXIT

bash scripts/ci/check_g2f_source_binding_v2.sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s conformance/g2f -p 'test_*.py'
bash scripts/g2f/check_g2f_conformance.sh
bash scripts/g2f/check_view_commitment_v2.sh

rustc --edition=2021 --test -D warnings \
  conformance/g2f/application_jmt_v1.rs -o "$jmt_binary"
"$jmt_binary"

cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-node --features g2f-namespace-test-support --lib
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-node --features g2f-namespace-test-support --lib -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check

restore_generated_state
trap - EXIT
git diff --check
test -z "$(git status --porcelain --untracked-files=all)"
