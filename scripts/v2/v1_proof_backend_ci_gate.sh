#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/trillionnium-rust"

cargo test -p trnm-pouw --lib tee_verifier_requires_cryptographic_backend_after_bound_envelope_validation
cargo test -p trnm-pouw --lib tee_verifier_backend_unavailable_maps_to_indeterminate
cargo test -p trnm-pouw --lib tee_verifier_valid_receipt_path_with_mock_backend
cargo test -p trnm-pouw --lib tee_verifier_invalid_receipt_path_with_mock_backend
cargo test -p trnm-pouw --lib zk_verifier_requires_cryptographic_backend_after_bound_envelope_validation
cargo test -p trnm-pouw --lib zk_verifier_backend_unavailable_maps_to_indeterminate
cargo test -p trnm-pouw --lib zk_verifier_valid_proof_path_with_mock_backend
cargo test -p trnm-pouw --lib zk_verifier_invalid_proof_path_with_mock_backend
cargo test -p trnm-pouw --lib zk_verifier_invalid_proof_path_rejects_mapped_public_inputs
cargo test -p trnm-pouw --lib registry_with_builtin_verifiers_fail_closed_when_task_id_binding_missing

echo "[PASS] V1 proof backend CI gate"
