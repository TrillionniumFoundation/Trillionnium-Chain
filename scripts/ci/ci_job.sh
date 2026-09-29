#!/usr/bin/env bash
set -euo pipefail
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
case "${1:?required job}" in
  repository-truth)
    bash scripts/project-preflight.sh --audit
    python3 scripts/ci/check_repository.py
    python3 scripts/ci/test_repository.py
    python3 scripts/ci/test_invariants_registry.py
    ;;
  protocol-contract)
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives -p trnm-checkpoint-types -p trnm-verification-profiles --all-targets --all-features
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol --all-targets --all-features
    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee --examples
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-transport proof_admission --all-targets
    python3 formal/pon-nakamoto-v1/test_contracts.py
    python3 formal/pon-nakamoto-v1/test_invariants.py
    python3 formal/pon-nakamoto-v1/test_evaluation.py
    python3 formal/pon-nakamoto-v1/test_artifacts.py
    python3 formal/pon-nakamoto-v1/test_inference_receipt.py
    python3 formal/pon-nakamoto-v1/test_bounded_process.py
    python3 formal/pon-nakamoto-v1/test_model_contract.py
    python3 formal/pon-nakamoto-v1/test_work_backend.py
    python3 formal/pon-nakamoto-v1/test_strict_signature.py
    TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_native_execution.py
    TRNM_NATIVE_EXECUTOR="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_contracts.py
    TRNM_NATIVE_MODE=release python3 formal/pon-nakamoto-v1/test_interop.py
    TRNM_NATIVE_MODE=release python3 scripts/ci/test_pon_accepted_block.py
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
    python3 scripts/ci/check_pon_evidence.py
    python3 scripts/ci/test_pon_evidence.py
    ;;
  *) printf '%s\n' 'unknown CI job' >&2; exit 2 ;;
esac
