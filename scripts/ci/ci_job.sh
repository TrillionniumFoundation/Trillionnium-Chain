#!/usr/bin/env bash
set -euo pipefail
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
case "${1:?required job}" in
  repository-truth)
    bash scripts/project-preflight.sh --audit
    python3 scripts/ci/check_repository.py
    python3 scripts/ci/test_repository.py
    ;;
  protocol-contract)
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives -p trnm-checkpoint-types -p trnm-verification-profiles --all-targets --all-features
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol --all-targets --all-features
    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives --examples
    python3 formal/pon-nakamoto-v1/test_contracts.py
    TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
    ;;
  fuzz-smoke)
    python3 scripts/ci/test_repository.py
    python3 formal/pon-nakamoto-v1/test_reference.py
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives fixed_hash_text -- --nocapture
    ;;
  rust-baseline)
    cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features
    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --doc --all-features
    cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
    ;;
  external-evidence-contract)
    python3 scripts/ci/check_repository.py
    python3 scripts/ci/test_repository.py EvidenceBoundaryTests
    ;;
  *) printf '%s\n' 'unknown CI job' >&2; exit 2 ;;
esac
