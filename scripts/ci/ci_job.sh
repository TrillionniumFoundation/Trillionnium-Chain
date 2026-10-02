#!/usr/bin/env bash
set -euo pipefail
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
case "${1:?required job}" in
  repository-truth)
    bash scripts/project-preflight.sh --audit
    python3 scripts/ci/test_project_boundary.py
    python3 scripts/ci/check_repository.py
    python3 scripts/refresh_distributed_source_inventory.py --check
    python3 scripts/ci/test_repository.py
    python3 scripts/ci/test_invariants_registry.py
    python3 scripts/ci/test_responsibility_evidence.py
    python3 scripts/ci/test_applicability.py
    python3 scripts/ci/test_work_cost_report.py
    python3 scripts/test_qualification_runtime.py
    ;;
  protocol-contract)
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives -p trnm-checkpoint-types -p trnm-verification-profiles --all-targets --all-features
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol --all-targets --all-features
    cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives -p trnm-mvcc-fee --examples
    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-transport proof_admission --all-targets
    python3 formal/pon-nakamoto-v1/test_contracts.py
    python3 formal/pon-nakamoto-v1/test_invariants.py
    cargo fetch --locked --manifest-path trillionnium/Cargo.toml
    cargo build --offline --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --bins --examples
    cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test qualified_tasks --test protected_ingress --test task_lifecycle --test task_lifecycle_v3 --test task_lifecycle_v4 --test public_evaluation --test public_intake_v2 --test public_cli --test local_mempool --test pool_mining --test public_pool_v3 --test public_pool_cli --test public_v3_observer --test pinned_peer_polling --test ancestry_long_sync --test distributed_roles
    TRNM_DISTRIBUTED_TEST_BINARY="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/distributed_pipeline" TRNM_DISTRIBUTED_TEST_OUTPUT="${RUNNER_TEMP:-/tmp}/trnm-distributed-conformance-$$" cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test distributed_roles -- --ignored --test-threads=1
    python3 scripts/test_llm_runtime_pilot.py
    python3 formal/pon-nakamoto-v1/test_model_attribution.py
    python3 formal/pon-nakamoto-v1/test_work_utility.py
    python3 formal/pon-nakamoto-v1/test_public_evaluation_lifecycle.py
    python3 formal/pon-nakamoto-v1/test_llm_adapter_contract.py
    python3 formal/pon-nakamoto-v1/test_model_acceptance.py
    "${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/continuous_pipeline" "${RUNNER_TEMP:-/tmp}/trnm-pipeline-smoke-$$" 2 4 0 growth protected
    python3 formal/pon-nakamoto-v1/test_evaluation_round.py
    python3 formal/pon-nakamoto-v1/test_evaluation.py
    python3 formal/pon-nakamoto-v1/test_evaluation_bundle.py
    python3 formal/pon-nakamoto-v1/test_artifacts.py
    python3 formal/pon-nakamoto-v1/test_inference_receipt.py
    python3 formal/pon-nakamoto-v1/test_bounded_process.py
    python3 formal/pon-nakamoto-v1/test_client_confirmation.py
    python3 formal/pon-nakamoto-v1/test_native_session.py
    python3 formal/pon-nakamoto-v1/test_work_precheck.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_SESSION="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute_session" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_client_confirmation.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_SESSION="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute_session" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_contracts.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_SESSION="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute_session" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_invariants.py
    TRNM_NATIVE_WORK="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_work_io" TRNM_NATIVE_EXECUTOR="${CARGO_TARGET_DIR:-trillionnium/target}/release/examples/pon_execute" TRNM_EXECUTION_WORKERS=8 python3 formal/pon-nakamoto-v1/test_client_confirmation.py
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
    # The workspace run includes evaluation_sync_observation. Do not duplicate
    # its ten-minute lifecycle here: job 110686611584 passed it twice, then hit
    # the unchanged 45-minute job budget before completing the remaining suite.
    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features
    cargo test --locked --manifest-path trillionnium/Cargo.toml --workspace --doc --all-features
    cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
    ;;
  external-evidence-contract)
    python3 scripts/ci/prepare_evidence_sources.py
    python3 scripts/ci/test_evidence_sources.py
    python3 scripts/ci/check_repository.py
    python3 scripts/ci/test_repository.py EvidenceBoundaryTests
    python3 scripts/ci/check_pon_evidence.py
    python3 scripts/ci/test_pon_evidence.py
    python3 scripts/ci/check_invariant_evidence.py --historical
    python3 scripts/ci/test_invariant_evidence.py
    python3 scripts/ci/check_completion_evidence.py --historical
    python3 scripts/ci/test_completion_evidence.py
    python3 scripts/ci/check_evaluation_bundle_evidence.py --historical
    python3 scripts/ci/check_client_confirmation_evidence.py --historical
    python3 scripts/ci/check_client_confirmation_evidence.py --historical --evidence evidence/pon-native-session-v1
    python3 scripts/ci/check_client_confirmation_evidence.py --historical --evidence evidence/pon-native-node-v1
    python3 scripts/ci/check_client_confirmation_evidence.py --historical --evidence evidence/pon-closed-round-v1
    python3 scripts/ci/check_public_readiness_evidence.py --historical --evidence evidence/pon-public-readiness-v1
    python3 scripts/ci/test_public_readiness_evidence.py
    python3 scripts/ci/check_native_node_supplements.py --historical
    python3 scripts/ci/test_native_node_supplements.py
    python3 scripts/ci/test_native_session_evidence.py
    python3 scripts/ci/test_client_confirmation_evidence.py
    python3 scripts/ci/test_evaluation_bundle_evidence.py
    python3 scripts/ci/report_module_evidence.py --format markdown
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-contract-authority-v1/work-cost --historical
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-native-session-v1/work-cost --historical
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-native-node-v1/work-cost --historical
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-closed-round-v1/work-cost --historical
    python3 scripts/ci/check_four_priority_evidence.py
    python3 scripts/ci/test_four_priority_evidence.py
    python3 scripts/pon_work_cost_report.py --verify evidence/pon-four-priority-audit-v1/work-cost --historical
    ;;
  *) printf '%s\n' 'unknown CI job' >&2; exit 2 ;;
esac
