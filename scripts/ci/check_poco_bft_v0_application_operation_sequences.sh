#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
vector="$repo_root/docs/protocol/poco-bft-v0/vectors/poco-application-operation-sequences-v0.json"

node "$repo_root/scripts/ci/author_poco_bft_v0_application_sequences.mjs" \
  check-final --vector "$vector"

(
  cd "$repo_root/trillionnium"
  cargo test -p trnm-consensus-app --lib \
    poco_application_operation_sequences_final_vector_matches_rust_replay \
    -- --nocapture
)
