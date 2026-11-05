#!/usr/bin/env bash
set -euo pipefail
cd /workspace/scratch/29755d2a47ef/chain-integrate-verified
export PATH=/workspace/shared/chain-cargo/bin:$PATH CARGO_HOME=/workspace/shared/chain-cargo RUSTUP_HOME=/workspace/shared/chain-rustup CARGO_TARGET_DIR=/workspace/shared/chain-growth-target RUST_TEST_THREADS=1
bash scripts/project-preflight.sh
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo metadata --manifest-path trillionnium/Cargo.toml --all-features --locked --offline --format-version 1 >/tmp/schema-combined-graph.json
for selector in store::native_authenticated ingress::public_v3 account_prefix_tests account_archive_prototype::native_store::tests account_archive_prototype::native_primitive_tests store::growth::tests store::reverse_path::tests store::history_page::tests; do
  cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-pon-node --lib "$selector" >"/tmp/schema-combined-${selector//::/_}.log" 2>&1
  tail -3 "/tmp/schema-combined-${selector//::/_}.log"
done
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline --workspace --all-targets --all-features -- -D warnings >/tmp/schema-combined-clippy.log 2>&1
tail -3 /tmp/schema-combined-clippy.log
