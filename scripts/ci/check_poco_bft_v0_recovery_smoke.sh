#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
python3 scripts/ci/check_native_consensus_only.py
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-native-application -p trnm-state-sync-v0
