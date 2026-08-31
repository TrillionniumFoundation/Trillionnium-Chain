#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
vector="$repo_root/docs/protocol/poco-bft-v0/vectors/poco-application-operation-sequences-v0.json"
legacy_manifest="$repo_root/trillionnium/crates/trnm-consensus-app/Cargo.toml"

node "$repo_root/scripts/ci/author_poco_bft_v0_application_sequences.mjs" \
  check-final --vector "$vector"

# trnm-consensus-app is deliberately excluded from the active Native PoCO-BFT
# workspace.  Replay this retained Comet-era differential oracle only through
# its self-contained archive workspace; never resolve it as an active package.
CARGO_TARGET_DIR="${RUNNER_TEMP:-/tmp}/trnm-consensus-app-differential-target" \
  cargo test \
    --manifest-path "$legacy_manifest" \
    --locked \
    --lib \
    poco_application_operation_sequences_final_vector_matches_rust_replay \
    -- --nocapture
