set -euo pipefail
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
    python3 scripts/ci/run_supply_chain.py
    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --doc --all-features
    cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
