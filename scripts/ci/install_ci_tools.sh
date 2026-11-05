#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/tool-versions.env
tool_root="${TRNM_CI_TOOL_ROOT:-${RUNNER_TEMP:-/tmp}/trnm-ci-tools}"
case "${1:?expected fuzz or supply-chain}" in
  fuzz)
    rustup toolchain install "$TRNM_FUZZ_TOOLCHAIN" --profile minimal --component rust-src
    cargo install --locked --version "=$TRNM_CARGO_FUZZ_VERSION" --root "$tool_root/fuzz-$TRNM_CARGO_FUZZ_VERSION" cargo-fuzz
    test "$("$tool_root/fuzz-$TRNM_CARGO_FUZZ_VERSION/bin/cargo-fuzz" --version)" = "cargo-fuzz $TRNM_CARGO_FUZZ_VERSION"
    ;;
  supply-chain)
    cargo install --locked --version "=$TRNM_CARGO_DENY_VERSION" --root "$tool_root/deny-$TRNM_CARGO_DENY_VERSION" cargo-deny
    test "$("$tool_root/deny-$TRNM_CARGO_DENY_VERSION/bin/cargo-deny" --version)" = "cargo-deny $TRNM_CARGO_DENY_VERSION"
    ;;
  *) printf '%s\n' 'unknown CI tool set' >&2; exit 2 ;;
esac
