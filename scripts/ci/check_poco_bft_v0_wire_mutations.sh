#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"

# This is intentionally a deterministic unit-corpus gate rather than a
# time-based libFuzzer campaign. It exhaustively mutates every byte of the
# canonical envelope, checks every strict truncation, and runs a fixed
# pseudo-random corpus. The test has no network or activation side effects.
cd "$REPO_ROOT/trillionnium"
cargo test --locked -p trnm-consensus-types \
  wire_envelope::tests::preflight_deterministic_mutation_corpus_is_total_and_fail_closed \
  -- --exact

printf '%s\n' \
  "wire_envelope_mutation_corpus=passed deterministic=single-byte-all-values+truncation+fixed-random"
