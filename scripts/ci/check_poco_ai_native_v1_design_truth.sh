#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
V1_ROOT="$ROOT/docs/protocol/poco-ai-native-v1"

STATUS="$V1_ROOT/status.toml"
MANIFEST="$V1_ROOT/spec-manifest.toml"
PARAMETERS="$V1_ROOT/parameters.toml"
STACK_PROFILE="$V1_ROOT/profiles/stack-reference-shadow.toml"
VERIFICATION_REGISTRY="$V1_ROOT/profiles/verification-registry-reference.toml"
SCHEMA_README="$V1_ROOT/schema/README.md"
OBJECT_CATALOG="$V1_ROOT/schema/object-catalog-v1.toml"
FOUNDATION_SCHEMA="$V1_ROOT/schema/cev1-foundation-order-kernel-v1.json"
ORDER_FINALITY_LIGHT_CLIENT_SCHEMA="$V1_ROOT/schema/cev1-order-finality-light-client-kernel-v1.json"
ORDER_TRUST_PATH_SCHEMA="$V1_ROOT/schema/cev1-order-trust-path-iterator-v1.json"
WEAK_SUBJECTIVITY_RENEWAL_SCHEMA="$V1_ROOT/schema/cev1-weak-subjectivity-checkpoint-renewal-v1.json"
CROSS_VERSION_ACTIVATION_PROOF_SCHEMA="$V1_ROOT/schema/cev1-cross-version-activation-proof-kernel-v1.json"
UPGRADE_SCHEMA="$V1_ROOT/schema/v0-to-v1-activation-kernel-v1.json"
VECTORS_README="$V1_ROOT/vectors/README.md"
FOUNDATION_VECTORS="$V1_ROOT/vectors/cev1-foundation-order-kernel-v1.json"
ORDER_CRYPTO_VECTORS="$V1_ROOT/vectors/cev1-order-signature-crypto-v1.json"
ORDER_FINALITY_LIGHT_CLIENT_VECTORS="$V1_ROOT/vectors/cev1-order-finality-light-client-kernel-v1.json"
ORDER_TRUST_PATH_VECTORS="$V1_ROOT/vectors/cev1-order-trust-path-iterator-v1.json"
ORDINARY_FINALITY_ADVANCE_VECTORS="$V1_ROOT/vectors/cev1-order-ordinary-finality-advance-v1.json"
WEAK_SUBJECTIVITY_RENEWAL_VECTORS="$V1_ROOT/vectors/cev1-weak-subjectivity-checkpoint-renewal-v1.json"
CROSS_VERSION_ACTIVATION_PROOF_VECTORS="$V1_ROOT/vectors/cev1-cross-version-activation-proof-kernel-v1.json"
UPGRADE_VECTORS="$V1_ROOT/vectors/v0-to-v1-activation-kernel-v1.json"
FOUNDATION_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_foundation_vectors.py"
FOUNDATION_INDEPENDENT_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_foundation_independent.py"
FOUNDATION_INDEPENDENT_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_foundation_independent.sh"
FOUNDATION_FORMAL_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_foundation_formal.sh"
ORDER_CRYPTO_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_crypto.py"
ORDER_CRYPTO_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_order_crypto.sh"
ORDER_FINALITY_LIGHT_CLIENT_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py"
ORDER_FINALITY_LIGHT_CLIENT_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_order_finality_light_client.sh"
ORDER_TRUST_PATH_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_order_trust_path_iterator.sh"
ORDINARY_FINALITY_ADVANCE_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_order_ordinary_finality_advance.sh"
WEAK_SUBJECTIVITY_RENEWAL_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_weak_subjectivity_renewal.sh"
CROSS_VERSION_ACTIVATION_PROOF_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_cross_version_activation_proof.py"
CROSS_VERSION_ACTIVATION_PROOF_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_cross_version_activation_proof.sh"
TRANSACTION_BATCH_DA_SCHEMA="$V1_ROOT/schema/cev1-transaction-batch-da-kernel-v1.json"
TRANSACTION_BATCH_DA_VECTORS="$V1_ROOT/vectors/cev1-transaction-batch-da-kernel-v1.json"
TRANSACTION_BATCH_DA_GATE="$ROOT/scripts/ci/check_trnm_poco_da_v1_boundary.sh"
AGENT_MARKET_SCHEMA="$V1_ROOT/schema/cev1-agent-market-kernel-v1.json"
AGENT_MARKET_VECTORS="$V1_ROOT/vectors/cev1-agent-market-kernel-v1.json"
AGENT_MARKET_GATE="$ROOT/scripts/ci/check_trnm_poco_agent_market_v1_boundary.sh"
VERIFY_CHALLENGE_SCHEMA="$V1_ROOT/schema/cev1-verify-challenge-kernel-v1.json"
VERIFY_CHALLENGE_VECTORS="$V1_ROOT/vectors/cev1-verify-challenge-kernel-v1.json"
VERIFY_CHALLENGE_GATE="$ROOT/scripts/ci/check_trnm_poco_verify_challenge_v1_boundary.sh"
OBJECT_MVCC_FEE_SCHEMA="$V1_ROOT/schema/cev1-object-mvcc-fee-kernel-v1.json"
OBJECT_MVCC_FEE_VECTORS="$V1_ROOT/vectors/cev1-object-mvcc-fee-kernel-v1.json"
OBJECT_MVCC_FEE_GATE="$ROOT/scripts/ci/check_trnm_poco_mvcc_fee_v1_boundary.sh"
CONSUMPTION_SETTLEMENT_SCHEMA="$V1_ROOT/schema/cev1-consumption-settlement-kernel-v1.json"
CONSUMPTION_SETTLEMENT_VECTORS="$V1_ROOT/vectors/cev1-consumption-settlement-kernel-v1.json"
CONSUMPTION_SETTLEMENT_GATE="$ROOT/scripts/ci/check_trnm_poco_consumption_settlement_v1_boundary.sh"
CROSS_PLANE_READBACK_SCHEMA="$V1_ROOT/schema/cev1-cross-plane-readback-kernel-v1.json"
CROSS_PLANE_READBACK_VECTORS="$V1_ROOT/vectors/cev1-cross-plane-readback-kernel-v1.json"
CROSS_PLANE_READBACK_GATE="$ROOT/scripts/ci/check_trnm_poco_cross_plane_readback_v1_boundary.sh"
CROSS_PLANE_CHECKPOINT_GATE="$ROOT/scripts/ci/check_trnm_poco_cross_plane_checkpoint_v1_boundary.sh"
ORDER_STATE_GATE="$ROOT/scripts/ci/check_trnm_poco_order_state_v1_boundary.sh"
GLOBAL_EXECUTION_GATE="$ROOT/scripts/ci/check_trnm_poco_global_execution_v1_boundary.sh"
GLOBAL_EXECUTION_BINDING_SCHEMA="$V1_ROOT/schema/cev1-global-execution-binding-kernel-v1.json"
GLOBAL_EXECUTION_BINDING_VECTORS="$V1_ROOT/vectors/cev1-global-execution-binding-kernel-v1.json"
GLOBAL_EXECUTION_BINDING_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_global_execution_binding.py"
UPGRADE_CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_upgrade_kernel.py"
UPGRADE_GATE="$ROOT/scripts/ci/check_poco_ai_native_v1_upgrade_kernel.sh"

fail() {
  printf 'PoCO AI-native v1 draft status/inventory gate failed: %s\n' "$*" >&2
  exit 1
}

required_files=(
  "$STATUS"
  "$MANIFEST"
  "$PARAMETERS"
  "$STACK_PROFILE"
  "$VERIFICATION_REGISTRY"
  "$SCHEMA_README"
  "$OBJECT_CATALOG"
  "$FOUNDATION_SCHEMA"
  "$ORDER_FINALITY_LIGHT_CLIENT_SCHEMA"
  "$ORDER_TRUST_PATH_SCHEMA"
  "$WEAK_SUBJECTIVITY_RENEWAL_SCHEMA"
  "$CROSS_VERSION_ACTIVATION_PROOF_SCHEMA"
  "$UPGRADE_SCHEMA"
  "$VECTORS_README"
  "$FOUNDATION_VECTORS"
  "$ORDER_CRYPTO_VECTORS"
  "$ORDER_FINALITY_LIGHT_CLIENT_VECTORS"
  "$ORDER_TRUST_PATH_VECTORS"
  "$WEAK_SUBJECTIVITY_RENEWAL_VECTORS"
  "$CROSS_VERSION_ACTIVATION_PROOF_VECTORS"
  "$UPGRADE_VECTORS"
  "$AGENT_MARKET_SCHEMA"
  "$AGENT_MARKET_VECTORS"
  "$VERIFY_CHALLENGE_SCHEMA"
  "$VERIFY_CHALLENGE_VECTORS"
  "$OBJECT_MVCC_FEE_SCHEMA"
  "$OBJECT_MVCC_FEE_VECTORS"
  "$CONSUMPTION_SETTLEMENT_SCHEMA"
  "$CONSUMPTION_SETTLEMENT_VECTORS"
  "$CROSS_PLANE_READBACK_SCHEMA"
  "$CROSS_PLANE_READBACK_VECTORS"
  "$GLOBAL_EXECUTION_BINDING_SCHEMA"
  "$GLOBAL_EXECUTION_BINDING_VECTORS"
  "$FOUNDATION_CHECKER"
  "$FOUNDATION_INDEPENDENT_CHECKER"
  "$FOUNDATION_INDEPENDENT_GATE"
  "$FOUNDATION_FORMAL_CHECKER"
  "$ORDER_CRYPTO_CHECKER"
  "$ORDER_CRYPTO_GATE"
  "$ORDER_FINALITY_LIGHT_CLIENT_CHECKER"
  "$ORDER_FINALITY_LIGHT_CLIENT_GATE"
  "$ORDER_TRUST_PATH_GATE"
  "$WEAK_SUBJECTIVITY_RENEWAL_GATE"
  "$CROSS_VERSION_ACTIVATION_PROOF_CHECKER"
  "$CROSS_VERSION_ACTIVATION_PROOF_GATE"
  "$UPGRADE_CHECKER"
  "$UPGRADE_GATE"
  "$AGENT_MARKET_GATE"
  "$VERIFY_CHALLENGE_GATE"
  "$OBJECT_MVCC_FEE_GATE"
  "$CONSUMPTION_SETTLEMENT_GATE"
  "$CROSS_PLANE_READBACK_GATE"
  "$CROSS_PLANE_CHECKPOINT_GATE"
  "$ORDER_STATE_GATE"
  "$GLOBAL_EXECUTION_GATE"
  "$GLOBAL_EXECUTION_BINDING_CHECKER"
  "$ROOT/scripts/ci/check_poco_ai_native_v1_design_truth.sh"
)

for required in "${required_files[@]}"; do
  [[ -f "$required" ]] || fail "missing required file: ${required#$ROOT/}"
done

python3 - \
  "$ROOT" \
  "$STATUS" \
  "$MANIFEST" \
  "$PARAMETERS" \
  "$STACK_PROFILE" \
  "$VERIFICATION_REGISTRY" \
  "$OBJECT_CATALOG" \
  "$SCHEMA_README" \
  "$VECTORS_README" \
  "$FOUNDATION_VECTORS" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
import tomllib

(
    root_raw,
    status_raw,
    manifest_raw,
    parameters_raw,
    stack_profile_raw,
    verification_registry_raw,
    object_catalog_raw,
    schema_readme_raw,
    vectors_readme_raw,
    foundation_vectors_raw,
) = sys.argv[1:]

root = pathlib.Path(root_raw)
paths = {
    "status": pathlib.Path(status_raw),
    "manifest": pathlib.Path(manifest_raw),
    "parameters": pathlib.Path(parameters_raw),
    "stack_profile": pathlib.Path(stack_profile_raw),
    "verification_registry": pathlib.Path(verification_registry_raw),
    "object_catalog": pathlib.Path(object_catalog_raw),
}


def load_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


documents = {name: load_toml(path) for name, path in paths.items()}
issues: list[str] = []


def expect(document: dict, label: str, key: str, expected: object) -> None:
    actual = document.get(key)
    if type(actual) is not type(expected) or actual != expected:
        issues.append(
            f"{label}.{key}={actual!r} ({type(actual).__name__}), "
            f"expected {expected!r} ({type(expected).__name__})"
        )


def expect_table(document: dict, label: str, key: str) -> dict:
    actual = document.get(key)
    if not isinstance(actual, dict):
        issues.append(f"{label}.{key} must be a TOML table")
        return {}
    return actual


def expect_keys(document: dict, label: str, expected: set[str]) -> None:
    actual = set(document)
    if actual != expected:
        issues.append(
            f"{label} keys={sorted(actual)!r}, expected {sorted(expected)!r}"
        )


protocol_id = "trnm-poco-ai-native-v1"
baseline = "poco-bft-v0"
plane_ids = [
    "agent",
    "market-task",
    "compute-verify",
    "data-availability",
    "order-coordination-settlement",
]
plane_status_keys = {
    "agent": "agent",
    "market-task": "market_task",
    "compute-verify": "compute_verify",
    "data-availability": "data_availability",
    "order-coordination-settlement": "order_coordination_settlement",
}

status = documents["status"]
expect_keys(status, "status", {
    "schema_version", "truth_id", "protocol_id", "protocol_major",
    "architecture_status", "specification_status", "normative_freeze",
    "design_only", "current_implementation_baseline", "implementation_status",
    "node_support", "protocol_activation", "production_candidate",
    "release_ready", "order_safety_kernel", "new_bft_safety_theorem",
    "planes", "evidence", "evidence_tranches",
})
for key, expected_value in {
    "schema_version": 1,
    "truth_id": "trnm-poco-ai-native-v1-design-truth-v1",
    "protocol_id": protocol_id,
    "protocol_major": 1,
    "architecture_status": "adopted",
    "specification_status": "draft",
    "normative_freeze": False,
    "design_only": True,
    "current_implementation_baseline": baseline,
    "implementation_status": "not-implemented",
    "node_support": False,
    "protocol_activation": False,
    "production_candidate": False,
    "release_ready": False,
    "order_safety_kernel": "weighted-chained-hotstuff-derived",
    "new_bft_safety_theorem": False,
}.items():
    expect(status, "status", key, expected_value)

planes = expect_table(status, "status", "planes")
if set(planes) != set(plane_status_keys.values()):
    issues.append(
        f"status.planes keys={sorted(planes)!r}, "
        f"expected {sorted(plane_status_keys.values())!r}"
    )
for key in plane_status_keys.values():
    expect(planes, "status.planes", key, "design-only")

evidence = expect_table(status, "status", "evidence")
expected_evidence_keys = {
    "wire_schemas_complete",
    "conformance_vectors_complete",
    "formal_model_complete",
    "light_client_spec_complete",
    "upgrade_contract_complete",
    "independent_review_complete",
    "interoperability_complete",
    "wan_fault_evidence",
    "performance_evidence",
}
if set(evidence) != expected_evidence_keys:
    issues.append(
        f"status.evidence keys={sorted(evidence)!r}, "
        f"expected {sorted(expected_evidence_keys)!r}"
    )
for key in expected_evidence_keys:
    expect(evidence, "status.evidence", key, False)

evidence_tranches = expect_table(status, "status", "evidence_tranches")
expect_keys(
    evidence_tranches,
    "status.evidence_tranches",
    {
        "foundation_order_kernel",
        "order_signature_crypto",
        "order_finality_light_client",
        "order_trust_path_iterator",
        "order_ordinary_finality_advance",
        "weak_subjectivity_checkpoint_renewal",
        "v0_to_v1_activation_kernel",
        "cross_version_activation_proof",
        "transaction_batch_da_kernel",
        "agent_market_kernel",
        "verify_challenge_kernel",
        "object_mvcc_fee_kernel",
        "consumption_settlement_kernel",
        "cross_plane_fresh_readback",
        "cross_plane_checkpoint_admission",
        "g2_candidate_aggregate",
        "global_pre_vote_execution_candidate",
        "manifest_bound_candidate_local_node_persistence",
    },
)

manifest_bound_node_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "manifest_bound_candidate_local_node_persistence",
)
expected_manifest_bound_node_evidence = {
    "classification": "candidate-non-normative",
    "scope": "exact-manifest-bound-finalize-join-data-journal-normal-node-process-and-fresh-typed-recovery",
    "exact_finalize_join_only_owner_ingress": True,
    "candidate_local_owner_non_clone": True,
    "complete_canonical_join_snapshot": True,
    "snapshot_or_record_owner_issuer": False,
    "sqlite_anchor_successor_history": True,
    "successor_only_compare_and_swap": True,
    "mandatory_fresh_source_readback": True,
    "mandatory_fresh_target_readback": True,
    "immutable_read_only_preflight": True,
    "read_write_file_identity_recheck": True,
    "path_hash_separate_connection_toctou_narrowed": True,
    "descriptor_bound_openat_identity": False,
    "same_uid_rename_race_closed": False,
    "namespace_identity_and_owner_pinned": False,
    "external_trusted_pin_required": True,
    "external_trusted_prefix_response_loss_resolution": True,
    "external_pin_reopen_executed": True,
    "fresh_exact_typed_join_recovery_required": True,
    "fresh_exact_typed_join_recovery_executed": True,
    "candidate_local_owner_retains_live_journal": True,
    "candidate_local_owner_fresh_exact_revalidation": True,
    "external_pin_process_persisted": True,
    "external_pin_authenticated_process_owner": True,
    "normal_binary_process_integration_tests_checked": 7,
    "real_five_source_process_fixture_complete": True,
    "two_process_response_loss_recovery_executed": True,
    "dynamic_negative_classes_checked": 5,
    "journal_only_authority": False,
    "whole_node_checkpoint_integration": False,
    "source_plane_apply": False,
    "vote_eligibility": False,
    "signing_authority": False,
    "node_process_integration": True,
    "anti_whole_store_rollback_authority": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    manifest_bound_node_evidence,
    "status.evidence_tranches.manifest_bound_candidate_local_node_persistence",
    set(expected_manifest_bound_node_evidence),
)
for key, expected_value in expected_manifest_bound_node_evidence.items():
    expect(
        manifest_bound_node_evidence,
        "status.evidence_tranches.manifest_bound_candidate_local_node_persistence",
        key,
        expected_value,
    )

foundation_order_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "foundation_order_kernel",
)
expected_foundation_order_evidence = {
    "classification": "candidate-non-normative",
    "schema_closed_for_listed_types": True,
    "positive_vectors_checked": 27,
    "derived_vectors_checked": 1,
    "negative_vectors_checked": 24,
    "independent_standard_library_parser": True,
    "independent_parser_self_tests": True,
    "strict_cev1_canonical_decode": True,
    "sha256_digest_reproduction": True,
    "cryptographic_signature_verification": False,
    "light_client_verifier": False,
    "upgrade_verifier": False,
}
expect_keys(
    foundation_order_evidence,
    "status.evidence_tranches.foundation_order_kernel",
    set(expected_foundation_order_evidence),
)
for key, expected_value in expected_foundation_order_evidence.items():
    expect(
        foundation_order_evidence,
        "status.evidence_tranches.foundation_order_kernel",
        key,
        expected_value,
    )

order_crypto_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "order_signature_crypto",
)
expected_order_crypto_evidence = {
    "classification": "candidate-non-normative",
    "signature_scheme": "strict-ed25519-v1-draft",
    "validator_count": 4,
    "vote_signature_claims_checked": 1,
    "timeout_signature_claims_checked": 2,
    "qc_signatures_checked": 4,
    "tc_signatures_checked": 4,
    "tc_entry_statements_checked": 4,
    "negative_cases_checked": 18,
    "independent_standard_library_verifier": True,
    "validator_set_digest_reproduction": True,
    "vote_timeout_domain_separation": True,
    "checked_weighted_quorum": True,
    "per_entry_timeout_statement_binding": True,
    "foundation_timeout_certificate_context_projection": True,
    "foundation_timeout_certificate_justification_projection": True,
    "full_crypto_interoperability": False,
    "light_client_verifier": False,
    "upgrade_verifier": False,
}
expect_keys(
    order_crypto_evidence,
    "status.evidence_tranches.order_signature_crypto",
    set(expected_order_crypto_evidence),
)
for key, expected_value in expected_order_crypto_evidence.items():
    expect(
        order_crypto_evidence,
        "status.evidence_tranches.order_signature_crypto",
        key,
        expected_value,
    )

order_finality_light_client_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "order_finality_light_client",
)
expected_order_finality_light_client_evidence = {
    "classification": "candidate-non-normative",
    "scope": "fresh-genesis-ordinary-checkpoint-and-one-epoch-handoff-bounded-trust-progression",
    "positive_cases_checked": 9,
    "negative_cases_checked": 212,
    "independent_standard_library_verifier": True,
    "raw_cev1_strict_decode": True,
    "exact_byte_reencoding": True,
    "expected_error_codes_checked": True,
    "foundation_schema_structural_exact_compare": True,
    "strict_ed25519_qc_verification": True,
    "strict_ed25519_tc_verification": True,
    "qc_signatures_checked": 60,
    "tc_signatures_checked": 4,
    "handoff_signatures_checked": 8,
    "direct_three_chain_finality": True,
    "checked_weighted_quorum": True,
    "fresh_genesis_trust_bundle": True,
    "validator_set_definition_hash_checked": True,
    "committed_parameter_constraints_checked": True,
    "fresh_genesis_empty_payload_checked": True,
    "finalized_target_fresh_genesis_only": False,
    "ordinary_target_finality": True,
    "ordinary_payload_bound_enforcement": False,
    "single_epoch_only": False,
    "consecutive_views_only": False,
    "single_skipped_view_tc": True,
    "checkpoint_finality_verification": True,
    "checkpoint_attachment_verification": True,
    "epoch_handoff_verification": True,
    "dual_role_context_isolation": True,
    "independent_old_new_weighted_quorum": True,
    "v1_handoff_first_finality": True,
    "post_handoff_ordinary_finality": True,
    "v0_activation_verification": False,
    "bounded_one_handoff_trust_progression": True,
    "arbitrary_length_multi_hop_light_client": False,
    "global_light_client_spec_complete": False,
}
expect_keys(
    order_finality_light_client_evidence,
    "status.evidence_tranches.order_finality_light_client",
    set(expected_order_finality_light_client_evidence),
)
for key, expected_value in expected_order_finality_light_client_evidence.items():
    expect(
        order_finality_light_client_evidence,
        "status.evidence_tranches.order_finality_light_client",
        key,
        expected_value,
    )

order_trust_path_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "order_trust_path_iterator",
)
expected_order_trust_path_evidence = {
    "classification": "candidate-non-normative",
    "scope": "bounded-zero-to-three-hop-fresh-genesis-then-checkpoint-anchored-order-trust-progression",
    "positive_hop_counts_checked": [0, 1, 2, 3],
    "replay_and_append_controls_checked": 2,
    "negative_cases_checked": 63,
    "max_hops": 3,
    "independent_standard_library_verifier": True,
    "raw_cev1_strict_decode": True,
    "exact_byte_reencoding": True,
    "digest_v1_construction_bound": True,
    "embedded_steps_independently_decoded": True,
    "existing_fresh_genesis_transition_position_zero_only": True,
    "versioned_checkpoint_anchored_later_steps": True,
    "intermediate_state_id_binding": True,
    "certified_head_qc_consumed": True,
    "strict_epoch_and_height_monotonicity": True,
    "handoff_protocol_sidecar_root_recomputed": True,
    "handoff_complete_wrapper_signatures_committed": True,
    "handoff_sidecar_root_negative_cases_checked": 3,
    "epoch_start_single_skipped_view_tc": True,
    "epoch_start_tc_safe_parent": "exact-epoch-handoff",
    "epoch_start_tc_locked_qc_absent": True,
    "epoch_start_tc_finalized_anchor": "exact-latest-epoch-checkpoint",
    "epoch_start_tc_negative_cases_checked": 11,
    "qc_signatures_checked": 88,
    "tc_signatures_checked": 4,
    "handoff_signatures_checked": 24,
    "openssl_signatures_cross_checked": 116,
    "v0_activation_verification": False,
    "weak_subjectivity_selection": False,
    "arbitrary_length_multi_hop_light_client": False,
    "complete_wire_crypto_corpus": False,
    "second_implementation_interoperability": False,
    "global_light_client_spec_complete": False,
    "normative_freeze": False,
    "implementation": False,
    "activation": False,
}
expect_keys(
    order_trust_path_evidence,
    "status.evidence_tranches.order_trust_path_iterator",
    set(expected_order_trust_path_evidence),
)
for key, expected_value in expected_order_trust_path_evidence.items():
    expect(
        order_trust_path_evidence,
        "status.evidence_tranches.order_trust_path_iterator",
        key,
        expected_value,
    )

ordinary_advance_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "order_ordinary_finality_advance",
)
expected_ordinary_advance_evidence = {
    "classification": "candidate-non-normative",
    "scope": "fresh-genesis-ordinary-target-then-two-bounded-same-epoch-ordinary-finality-advances",
    "positive_controls_checked": 4,
    "sequential_advances_checked": 2,
    "negative_cases_checked": 52,
    "independent_standard_library_verifier": True,
    "raw_cev1_strict_decode": True,
    "exact_byte_reencoding": True,
    "expected_error_codes_checked": True,
    "source_ordinary_target_proof_verified": True,
    "source_single_skipped_view_tc": True,
    "input_output_state_id_composition": True,
    "same_epoch_only": True,
    "exact_three_certified_headers_per_advance": True,
    "first_edge_consecutive": True,
    "later_single_skipped_view_tc": True,
    "max_skipped_views_per_advance": 1,
    "strict_ed25519_qc_verification": True,
    "strict_ed25519_tc_verification": True,
    "checked_weighted_quorum": True,
    "qc_signatures_checked": 40,
    "tc_signatures_checked": 8,
    "openssl_signatures_cross_checked": 48,
    "ordinary_three_chain_finality": True,
    "payload_execution_verified": False,
    "arbitrary_length_history": False,
    "complete_wire_crypto_corpus": False,
    "second_implementation_interoperability": False,
    "global_light_client_spec_complete": False,
    "normative_freeze": False,
    "implementation": False,
    "activation": False,
}
expect_keys(
    ordinary_advance_evidence,
    "status.evidence_tranches.order_ordinary_finality_advance",
    set(expected_ordinary_advance_evidence),
)
for key, expected_value in expected_ordinary_advance_evidence.items():
    expect(
        ordinary_advance_evidence,
        "status.evidence_tranches.order_ordinary_finality_advance",
        key,
        expected_value,
    )

weak_subjectivity_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "weak_subjectivity_checkpoint_renewal",
)
expected_weak_subjectivity_evidence = {
    "classification": "candidate-non-normative",
    "scope": "exact-three-hop-first-to-latest-checkpoint-anchor-renewal",
    "positive_controls_checked": 2,
    "negative_cases_checked": 45,
    "max_trust_path_hops": 3,
    "independent_standard_library_verifier": True,
    "raw_cev1_strict_decode": True,
    "exact_byte_reencoding": True,
    "first_and_latest_checkpoint_exact_binding": True,
    "chain_genesis_protocol_context_lineage": True,
    "checkpoint_epoch_binding": True,
    "checkpoint_validator_set_hash_binding": True,
    "checkpoint_consensus_parameters_hash_binding": True,
    "checkpoint_application_and_schema_root_binding": True,
    "prior_checkpoint_epoch_age_checked": True,
    "prior_checkpoint_block_age_checked": True,
    "strict_epoch_and_height_monotonicity": True,
    "same_height_conflict_rejection": True,
    "wall_clock_oracle": False,
    "operator_or_governance_authentication": False,
    "arbitrary_checkpoint_selection": False,
    "arbitrary_length_history": False,
    "complete_wire_crypto_corpus": False,
    "second_implementation_interoperability": False,
    "global_light_client_spec_complete": False,
    "normative_freeze": False,
    "implementation": False,
    "activation": False,
}
expect_keys(
    weak_subjectivity_evidence,
    "status.evidence_tranches.weak_subjectivity_checkpoint_renewal",
    set(expected_weak_subjectivity_evidence),
)
for key, expected_value in expected_weak_subjectivity_evidence.items():
    expect(
        weak_subjectivity_evidence,
        "status.evidence_tranches.weak_subjectivity_checkpoint_renewal",
        key,
        expected_value,
    )

upgrade_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "v0_to_v1_activation_kernel",
)
expected_upgrade_evidence = {
    "classification": "candidate-non-normative",
    "positive_cases_checked": 1,
    "negative_cases_checked": 31,
    "independent_standard_library_verifier": True,
    "frozen_v0_validator_set_hash_reproduction": True,
    "v1_validator_set_descriptor_hash_reproduction": True,
    "duplicate_validator_and_public_key_rejection": True,
    "independent_old_new_weighted_quorum": True,
    "strict_ed25519_role_domain_verification": True,
    "exact_epoch_boundary_and_no_fallback": True,
    "first_v1_empty_activation_block_projection": True,
    "complete_v0_authority_verification": False,
    "complete_migration_verification": False,
    "light_client_verifier": False,
    "upgrade_contract_complete": False,
}
expect_keys(
    upgrade_evidence,
    "status.evidence_tranches.v0_to_v1_activation_kernel",
    set(expected_upgrade_evidence),
)
for key, expected_value in expected_upgrade_evidence.items():
    expect(
        upgrade_evidence,
        "status.evidence_tranches.v0_to_v1_activation_kernel",
        key,
        expected_value,
    )

cross_version_activation_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "cross_version_activation_proof",
)
expected_cross_version_activation_evidence = {
    "classification": "candidate-non-normative",
    "positive_cases_checked": 1,
    "negative_cases_checked": 44,
    "raw_cev0_upgrade_plan_field12_exact": True,
    "frozen_v0_fields13_14_forbidden": True,
    "separate_cev1_activation_proof_carrier": True,
    "proposal_carrier_signatures_checked": 1,
    "qc_signatures_checked": 12,
    "three_chain_finality": True,
    "no_fallback_and_unique_boundary": True,
    "independent_old_new_weighted_quorum": True,
    "openssl_signature_cross_check": True,
    "governance_state_membership_verified": False,
    "complete_v0_authority_verification": False,
    "complete_migration_verification": False,
    "full_order_proposal_v1": False,
    "upgrade_contract_complete": False,
}
expect_keys(
    cross_version_activation_evidence,
    "status.evidence_tranches.cross_version_activation_proof",
    set(expected_cross_version_activation_evidence),
)
for key, expected_value in expected_cross_version_activation_evidence.items():
    expect(
        cross_version_activation_evidence,
        "status.evidence_tranches.cross_version_activation_proof",
        key,
        expected_value,
    )

transaction_batch_da_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "transaction_batch_da_kernel",
)
expected_transaction_batch_da_evidence = {
    "classification": "candidate-non-normative",
    "scope": "local-transaction-batch-namespace-only",
    "positive_cases_checked": 12,
    "negative_cases_checked": 20,
    "crash_and_reopen_cases_checked": 7,
    "typed_namespace_and_object_ids": True,
    "durable_before_attest": True,
    "attestation_high_watermark": True,
    "anti_whole_store_rollback_authority": False,
    "immutable_durable_manifest_checksum": True,
    "fresh_connection_exact_readback": True,
    "author_sequence_and_quota": True,
    "bounded_queue": True,
    "strict_ed25519_attestations": True,
    "checked_weighted_quorum": True,
    "canonical_unique_attestors": True,
    "retrieval_and_exact_repair": True,
    "signed_full_range_retrieval_proof_candidate": True,
    "proof_driven_exact_repair_candidate": True,
    "signed_retrieval_positive_cases_checked": 1,
    "signed_retrieval_negative_controls_checked": 14,
    "signed_retrieval_compile_fail_cases_checked": 4,
    "canonical_certified_chunk_inclusion_paths": True,
    "canonical_multilevel_chunk_paths_checked": True,
    "certificate_author_policy_key_binding": True,
    "repair_window_enforced": True,
    "authoritative_repair_height_source": False,
    "target_scope_store_config_certificate_binding": True,
    "generic_chunk_range_retrieval": False,
    "requester_registry_integration": False,
    "durable_responder_signer_journal": False,
    "withholding_adjudication": False,
    "retention_obligation_and_gc_tombstone": True,
    "gc_permit_nonconstructible": True,
    "production_gc_authority": False,
    "external_byte_deletion_reachable": False,
    "objective_signed_equivocation_evidence": True,
    "artifact_evidence_namespace": False,
    "network_service": False,
    "whole_node_checkpoint_integration": False,
    "node_integration": False,
    "data_availability_plane_implemented": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    transaction_batch_da_evidence,
    "status.evidence_tranches.transaction_batch_da_kernel",
    set(expected_transaction_batch_da_evidence),
)
for key, expected_value in expected_transaction_batch_da_evidence.items():
    expect(
        transaction_batch_da_evidence,
        "status.evidence_tranches.transaction_batch_da_kernel",
        key,
        expected_value,
    )

agent_market_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "agent_market_kernel",
)
expected_agent_market_evidence = {
    "classification": "candidate-non-normative",
    "scope": "local-capability-session-nonce-task-funded-escrow-bid-lease-and-order-finalized-context-only",
    "positive_cases_checked": 13,
    "negative_cases_checked": 58,
    "crash_and_reopen_cases_checked": 6,
    "strict_ed25519_authorization": True,
    "controller_lane_zero_namespace": True,
    "session_lane_zero_forbidden": True,
    "shared_capability_budget_across_lanes": True,
    "task_and_funded_escrow_atomic_create": True,
    "bid_active_to_consumed_one_shot": True,
    "lease_five_object_atomic_transition": True,
    "provider_offered_to_active": True,
    "account_escrow_bond_conservation": True,
    "exact_replay_and_fresh_reopen": True,
    "exact_operation_and_resource_scope_enforcement": True,
    "committed_resource_scope_verifier": False,
    "provider_accept_lease_to_task_resolution": True,
    "order_finalized_execution_context_cas": True,
    "order_proof_authority_complete": False,
    "sqlite_schema_version": 3,
    "automatic_migration": False,
    "sidecars_fail_closed": True,
    "durable_state_and_journal_roots_checked": True,
    "durable_finalized_order_block_journal": True,
    "third_state_permanent_fence": True,
    "whole_store_rollback_authority": False,
    "fresh_genesis_trust_bundle_consensus_object": False,
    "bootstrap_identity_key_derivation_authority_complete": False,
    "agent_transaction_wire_complete": False,
    "identity_and_key_lifecycle_complete": False,
    "verify_challenge_complete": False,
    "node_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    agent_market_evidence,
    "status.evidence_tranches.agent_market_kernel",
    set(expected_agent_market_evidence),
)
for key, expected_value in expected_agent_market_evidence.items():
    expect(
        agent_market_evidence,
        "status.evidence_tranches.agent_market_kernel",
        key,
        expected_value,
    )

verify_challenge_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "verify_challenge_kernel",
)
expected_verify_challenge_evidence = {
    "classification": "candidate-non-normative",
    "scope": "local-stake-quorum-receipt-evaluation-and-single-challenge-only",
    "positive_cases_checked": 16,
    "negative_cases_checked": 30,
    "crash_and_reopen_cases_checked": 6,
    "verification_class": "StakeQuorum",
    "all_seven_verification_classes_complete": False,
    "strict_ed25519_receipt_and_claims": True,
    "checked_weighted_quorum": True,
    "verifier_identity_unique_weight": True,
    "exact_claim_statement_evidence_sequence_binding": True,
    "required_da_policy_hash_bound": True,
    "bootstrap_duplicate_key_ids_and_public_keys_rejected": True,
    "committed_verifier_set_and_profile_hashes_recomputed": True,
    "atomic_begin_evaluation_and_decision": True,
    "challenge_bond_conservation": True,
    "evidence_response_adjudication": True,
    "artifact_evidence_da_verified": False,
    "withdraw_expire_appeal_complete": False,
    "multiple_concurrent_challenges": False,
    "settlement_integration_complete": False,
    "agent_market_integration_complete": False,
    "sqlite_schema_version": 3,
    "automatic_migration": False,
    "sidecars_fail_closed": True,
    "third_state_permanent_fence": True,
    "order_finalized_execution_context_cas": True,
    "order_proof_authority_complete": False,
    "durable_state_and_journal_tail_roots": True,
    "durable_finalized_order_block_journal": True,
    "whole_store_rollback_authority": False,
    "fresh_genesis_trust_bundle_consensus_object": False,
    "agent_transaction_wire_complete": False,
    "node_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    verify_challenge_evidence,
    "status.evidence_tranches.verify_challenge_kernel",
    set(expected_verify_challenge_evidence),
)
for key, expected_value in expected_verify_challenge_evidence.items():
    expect(
        verify_challenge_evidence,
        "status.evidence_tranches.verify_challenge_kernel",
        key,
        expected_value,
    )

object_mvcc_fee_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "object_mvcc_fee_kernel",
)
expected_object_mvcc_fee_evidence = {
    "classification": "candidate-non-normative",
    "scope": "local-single-block-object-mvcc-and-four-resource-fee-delta-only",
    "positive_cases_checked": 12,
    "negative_cases_checked": 39,
    "crash_and_reopen_cases_checked": 6,
    "canonical_serial_oracle": True,
    "deterministic_conflict_retry": True,
    "explicit_versioned_read_write_sets": True,
    "complete_success_reverted_out_of_resource_receipts": True,
    "resource_class_count": 4,
    "all_resource_classes_complete": False,
    "checked_fee_arithmetic": True,
    "per_transaction_fee_deltas": True,
    "block_end_sorted_fee_reduction": True,
    "global_fee_collector_per_transaction_write": False,
    "sqlite_schema_version": 1,
    "automatic_migration": False,
    "immutable_read_only_existing_file_preflight": True,
    "third_state_permanent_fence": True,
    "durable_state_and_block_journal_roots": True,
    "deterministic_journal_replay_audit": True,
    "whole_store_rollback_authority": False,
    "real_parallel_worker_pool": False,
    "authenticated_global_state_tree": False,
    "agent_transaction_wire_complete": False,
    "order_proof_authority_complete": False,
    "node_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    object_mvcc_fee_evidence,
    "status.evidence_tranches.object_mvcc_fee_kernel",
    set(expected_object_mvcc_fee_evidence),
)
for key, expected_value in expected_object_mvcc_fee_evidence.items():
    expect(
        object_mvcc_fee_evidence,
        "status.evidence_tranches.object_mvcc_fee_kernel",
        key,
        expected_value,
    )

consumption_settlement_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "consumption_settlement_kernel",
)
expected_consumption_settlement_evidence = {
    "classification": "candidate-non-normative",
    "scope": "local-single-asset-single-result-single-rollup-only",
    "positive_cases_checked": 10,
    "negative_cases_checked": 56,
    "crash_and_reopen_cases_checked": 6,
    "bilateral_ed25519_receipt_and_rollup_signatures": True,
    "monotonic_gap_free_receipt_chain": True,
    "checked_cumulative_usage_and_charge": True,
    "atomic_complete_rollup_assignment": True,
    "chain_assigned_rollup_challenge_window": True,
    "settlement_amounts_caller_selected": False,
    "checked_single_asset_conservation": True,
    "one_shot_atomic_settlement": True,
    "deterministic_journal_replay_audit": True,
    "sqlite_schema_version": 2,
    "automatic_migration": False,
    "immutable_read_only_existing_file_preflight": True,
    "third_state_permanent_fence": True,
    "durable_state_and_journal_roots": True,
    "durable_finalized_order_block_journal": True,
    "agent_market_authority_integration": False,
    "artifact_da_authority_integration": False,
    "result_challenge_authority_integration": False,
    "order_proof_authority_complete": False,
    "mvcc_final_apply_integration": False,
    "whole_store_rollback_authority": False,
    "node_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    consumption_settlement_evidence,
    "status.evidence_tranches.consumption_settlement_kernel",
    set(expected_consumption_settlement_evidence),
)
for key, expected_value in expected_consumption_settlement_evidence.items():
    expect(
        consumption_settlement_evidence,
        "status.evidence_tranches.consumption_settlement_kernel",
        key,
        expected_value,
    )

cross_plane_readback_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "cross_plane_fresh_readback",
)
expected_cross_plane_readback_evidence = {
    "classification": "candidate-non-normative",
    "scope": "five-local-store-double-sampled-fresh-readback-only",
    "positive_cases_checked": 3,
    "negative_cases_checked": 13,
    "compile_fail_cases_checked": 2,
    "fresh_reopen_each_store": True,
    "double_sample_no_intervening_change": True,
    "same_da_head_and_certificate_sqlite_snapshot": True,
    "explicit_typed_identifier_adapters": True,
    "same_protocol_context_and_order_head": True,
    "terminal_receipts_match_sampled_store_heads": True,
    "cross_plane_readback_consistent_candidate": True,
    "real_five_store_fixture_complete": False,
    "order_proof_authority_complete": False,
    "order_finalized_cross_plane_authority": False,
    "cross_plane_atomic_commit": False,
    "cross_plane_authority_integration": False,
    "whole_node_checkpoint_integration": False,
    "anti_whole_store_rollback_authority": False,
    "node_private_owner": False,
    "node_process_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    cross_plane_readback_evidence,
    "status.evidence_tranches.cross_plane_fresh_readback",
    set(expected_cross_plane_readback_evidence),
)
for key, expected_value in expected_cross_plane_readback_evidence.items():
    expect(
        cross_plane_readback_evidence,
        "status.evidence_tranches.cross_plane_fresh_readback",
        key,
        expected_value,
    )

cross_plane_checkpoint_evidence = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "cross_plane_checkpoint_admission",
)
expected_cross_plane_checkpoint_evidence = {
    "classification": "candidate-non-normative",
    "scope": "bounded-direct-order-verifier-authoritative-tag50-writer-and-local-membership-binding",
    "bounded_rust_order_verifier": True,
    "rust_order_verifier_unit_tests_checked": 15,
    "rust_order_verifier_compile_fail_cases_checked": 4,
    "rust_order_verifier_negative_classes_checked": 6,
    "raw_cev1_strict_decode": True,
    "exact_byte_reencoding": True,
    "verifier_local_absolute_input_bounds_before_hash_decode": True,
    "committed_max_retained_views_consumed": True,
    "strict_ed25519_qc_verification": True,
    "checked_weighted_quorum": True,
    "application_state_sparse_membership": True,
    "application_state_membership_unit_tests_checked": 2,
    "application_state_membership_negative_controls_checked": 3,
    "execution_binding_claim_strict_cev1": True,
    "execution_binding_claim_absolute_input_bound": True,
    "execution_binding_claim_distinct_ordered_witnesses": True,
    "execution_binding_claim_unit_tests_checked": 7,
    "execution_binding_claim_negative_controls_checked": 23,
    "execution_binding_positive_carrier_defined": True,
    "registered_execution_binding_state_object": True,
    "deterministic_execution_binding_create_material": True,
    "execution_binding_create_material_unit_tests_checked": 1,
    "authoritative_order_state_writer_unit_tests_checked": 11,
    "authoritative_order_state_writer_compile_fail_cases_checked": 5,
    "canonical_recovered_parent_manifest_bound_g2_seal": True,
    "canonical_receipt_claim_projection": True,
    "execution_binding_machine_schema_assigned": True,
    "execution_binding_machine_schema_closed_listed_types_only": True,
    "execution_binding_vector_positive_controls_checked": 6,
    "execution_binding_vector_negative_controls_checked": 51,
    "execution_binding_independent_stdlib_checker": True,
    "execution_binding_vector_terminal_positive_carrier": True,
    "authoritative_execution_binding_state_writer": True,
    "normal_execution_binding_issuer": True,
    "order_state_membership_binding": True,
    "independently_pinned_trust_digest": True,
    "fresh_genesis_rooted_direct_bounded_chain": True,
    "tc_supported": False,
    "ordinary_target_supported": True,
    "direct_ordinary_target_unit_tests_checked": 1,
    "certified_chain_ordinary_ancestry": True,
    "epoch_handoff_supported": False,
    "checkpoint_unit_tests_checked": 7,
    "checkpoint_positive_controls_checked": 3,
    "checkpoint_negative_controls_checked": 12,
    "fresh_five_store_rejoin_before_cas": True,
    "exact_initial_reconfirmation": True,
    "successor_only_checkpoint_cas": True,
    "mandatory_fresh_source_readback": True,
    "mandatory_fresh_target_readback": True,
    "applied_ack_lost_exact_target_recovery": True,
    "trust_pin_lineage_stable": True,
    "node_private_checkpoint_admission": True,
    "distinct_checkpoint_namespace": True,
    "immutable_read_only_existing_file_preflight": True,
    "rw_file_identity_revalidated_before_pragma_or_transaction": True,
    "rollback_journal_header_preflight": True,
    "sqlite_sidecars_rejected_before_open": True,
    "schema_rejection_byte_stable": True,
    "path_replacement_rejected": True,
    "order_finalized_cross_plane_authority": False,
    "cross_plane_source_atomicity": False,
    "whole_node_checkpoint_integration": False,
    "anti_whole_store_rollback_authority": False,
    "node_process_integration": False,
    "global_light_client_spec_complete": False,
    "g2_global_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    cross_plane_checkpoint_evidence,
    "status.evidence_tranches.cross_plane_checkpoint_admission",
    set(expected_cross_plane_checkpoint_evidence),
)
for key, expected_value in expected_cross_plane_checkpoint_evidence.items():
    expect(
        cross_plane_checkpoint_evidence,
        "status.evidence_tranches.cross_plane_checkpoint_admission",
        key,
        expected_value,
    )

g2_candidate_aggregate = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "g2_candidate_aggregate",
)
expected_g2_candidate_aggregate = {
    "classification": "candidate-non-normative",
    "bounded_local_candidate_tranches_present": ["G2A", "G2B", "G2C", "G2D", "G2E", "G2F"],
    "bounded_local_candidate_tranche_count": 6,
    "all_listed_boundary_gates_present": True,
    "cross_plane_readback_consistent_candidate": True,
    "global_pre_vote_candidate_runtime_implemented": True,
    "order_finalized_cross_plane_authority": False,
    "cross_plane_authority_integration": False,
    "end_to_end_transaction_execution": False,
    "whole_node_checkpoint_integration": False,
    "node_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    g2_candidate_aggregate,
    "status.evidence_tranches.g2_candidate_aggregate",
    set(expected_g2_candidate_aggregate),
)
for key, expected_value in expected_g2_candidate_aggregate.items():
    expect(
        g2_candidate_aggregate,
        "status.evidence_tranches.g2_candidate_aggregate",
        key,
        expected_value,
    )

global_pre_vote_execution_candidate = expect_table(
    evidence_tranches,
    "status.evidence_tranches",
    "global_pre_vote_execution_candidate",
)
expected_global_pre_vote_execution_candidate = {
    "classification": "candidate-non-normative",
    "scope": "single-certified-global-item-preview-validation-source-apply-and-local-terminal-facts-cas",
    "candidate_runtime_implemented": True,
    "positive_controls_checked": 7,
    "negative_controls_checked": 21,
    "compile_fail_cases_checked": 4,
    "certified_da_complete_retrieval_before_preview": True,
    "strict_single_item_codec": True,
    "agent_market_pre_vote_preview": True,
    "verify_challenge_pre_vote_preview": True,
    "mvcc_fee_pre_vote_preview": True,
    "consumption_settlement_pre_vote_preview": True,
    "candidate_composite_root": True,
    "whole_node_validation_sequence_cas": True,
    "mandatory_fresh_source_readback": True,
    "mandatory_fresh_target_readback": True,
    "prepared_target_reopen_checked": True,
    "whole_node_finalization_cas": True,
    "terminal_facts_single_transaction": True,
    "terminal_checkpoint_history_audit": True,
    "order_binding_owner_seam": True,
    "inert_order_binding_create_material": True,
    "order_binding_positive_carrier_issuer": False,
    "normal_build_finalization_owner_issuer": True,
    "source_plane_finalization_apply": True,
    "anti_whole_store_rollback_authority": False,
    "normative_application_jmt_root": False,
    "normative_agent_transaction_wire": False,
    "multi_level_speculative_overlay": False,
    "order_state_membership_binding": True,
    "order_proof_authority_complete": False,
    "node_process_integration": False,
    "g2_global_complete": False,
    "global_wire_schema_complete": False,
    "global_conformance_vectors_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
expect_keys(
    global_pre_vote_execution_candidate,
    "status.evidence_tranches.global_pre_vote_execution_candidate",
    set(expected_global_pre_vote_execution_candidate),
)
for key, expected_value in expected_global_pre_vote_execution_candidate.items():
    expect(
        global_pre_vote_execution_candidate,
        "status.evidence_tranches.global_pre_vote_execution_candidate",
        key,
        expected_value,
    )

manifest = documents["manifest"]
expect_keys(manifest, "manifest", {
    "schema_version", "manifest_id", "protocol_id", "protocol_major",
    "manifest_status", "normative", "implementation_authority",
    "activation_authority", "status_path", "parameters_path",
    "stack_profile_path", "verification_registry_path", "schema_readme_path",
    "object_catalog_path", "vectors_readme_path", "gap_register_path",
    "order_trust_path_schema_path", "order_trust_path_vectors_path",
    "order_trust_path_gate_path", "order_trust_path_negative_cases",
    "ordinary_finality_advance_schema_path",
    "ordinary_finality_advance_vectors_path",
    "ordinary_finality_advance_gate_path",
    "ordinary_finality_advance_negative_cases",
    "weak_subjectivity_renewal_schema_path",
    "weak_subjectivity_renewal_vectors_path",
    "weak_subjectivity_renewal_gate_path",
    "weak_subjectivity_renewal_negative_cases",
    "production_contracts_path", "delivery_plan_path", "formal_plan_path",
    "transport_schema_boundary_path", "required_files",
    "draft_candidate_normative_files", "plane_ids", "reference_profile_ids",
})
for key, expected_value in {
    "schema_version": 1,
    "manifest_id": "trnm-poco-ai-native-v1-support-manifest-v1",
    "protocol_id": protocol_id,
    "protocol_major": 1,
    "manifest_status": "draft-design-only",
    "normative": False,
    "implementation_authority": False,
    "activation_authority": False,
}.items():
    expect(manifest, "manifest", key, expected_value)

expected_manifest_files = [
    "docs/protocol/poco-ai-native-v1/README.md",
    "docs/protocol/poco-ai-native-v1/01-system-model-threat-model-and-non-goals.md",
    "docs/protocol/poco-ai-native-v1/02-versioning-chain-profile-wire-and-crypto.md",
    "docs/protocol/poco-ai-native-v1/03-agent-identity-capabilities-and-nonce-lanes.md",
    "docs/protocol/poco-ai-native-v1/04-market-task-lease-escrow-and-lifecycle.md",
    "docs/protocol/poco-ai-native-v1/05-compute-receipts-verification-and-challenges.md",
    "docs/protocol/poco-ai-native-v1/06-certified-data-availability.md",
    "docs/protocol/poco-ai-native-v1/07-order-consensus-epochs-and-finality.md",
    "docs/protocol/poco-ai-native-v1/08-coordination-settlement-execution-and-fees.md",
    "docs/protocol/poco-ai-native-v1/09-light-client-state-sync-and-upgrades.md",
    "docs/protocol/poco-ai-native-v1/10-invariants-formal-obligations-and-conformance.md",
    "docs/protocol/poco-ai-native-v1/status.toml",
    "docs/protocol/poco-ai-native-v1/spec-manifest.toml",
    "docs/protocol/poco-ai-native-v1/parameters.toml",
    "docs/protocol/poco-ai-native-v1/profiles/stack-reference-shadow.toml",
    "docs/protocol/poco-ai-native-v1/profiles/verification-registry-reference.toml",
    "docs/protocol/poco-ai-native-v1/schema/README.md",
    "docs/protocol/poco-ai-native-v1/schema/object-catalog-v1.toml",
    "docs/protocol/poco-ai-native-v1/schema/cev1-foundation-order-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-order-finality-light-client-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-order-trust-path-iterator-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-order-ordinary-finality-advance-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-weak-subjectivity-checkpoint-renewal-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-cross-version-activation-proof-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-transaction-batch-da-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-agent-market-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-verify-challenge-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-object-mvcc-fee-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-consumption-settlement-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-cross-plane-readback-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/cev1-global-execution-binding-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/schema/v0-to-v1-activation-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/README.md",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-foundation-order-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-order-signature-crypto-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-order-finality-light-client-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-order-trust-path-iterator-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-order-ordinary-finality-advance-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-weak-subjectivity-checkpoint-renewal-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-cross-version-activation-proof-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-transaction-batch-da-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-agent-market-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-verify-challenge-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-object-mvcc-fee-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-consumption-settlement-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-cross-plane-readback-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/cev1-global-execution-binding-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/vectors/v0-to-v1-activation-kernel-v1.json",
    "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md",
    "docs/architecture/TRNM_POCO_AI_NATIVE_V1_PRODUCTION_CONTRACTS.md",
    "docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md",
    "formal/quint/poco-ai-native-v1/README.md",
    "formal/quint/poco-ai-native-v1/weighted_order_kernel.qnt",
    "formal/quint/poco-ai-native-v1/timeout_lock.qnt",
    "formal/quint/poco-ai-native-v1/epoch_handoff_activation.qnt",
    "formal/quint/poco-ai-native-v1/mutants/duplicate_signer_weight.qnt",
    "formal/quint/poco-ai-native-v1/mutants/unsafe_lock_vote.qnt",
    "formal/quint/poco-ai-native-v1/mutants/tc_unlocks.qnt",
    "formal/quint/poco-ai-native-v1/mutants/tc_finalizes.qnt",
    "formal/quint/poco-ai-native-v1/mutants/two_chain_finality.qnt",
    "formal/quint/poco-ai-native-v1/mutants/single_quorum_handoff.qnt",
    "formal/quint/poco-ai-native-v1/mutants/wrong_activation_anchor.qnt",
    "proto/trnm/poco/ai/v1/README.md",
    "scripts/ci/check_poco_ai_native_v1_foundation_vectors.py",
    "scripts/ci/check_poco_ai_native_v1_foundation_independent.py",
    "scripts/ci/check_poco_ai_native_v1_foundation_independent.sh",
    "scripts/ci/check_poco_ai_native_v1_foundation_formal.sh",
    "scripts/ci/check_poco_ai_native_v1_order_crypto.py",
    "scripts/ci/check_poco_ai_native_v1_order_crypto.sh",
    "scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py",
    "scripts/ci/check_poco_ai_native_v1_order_finality_light_client.sh",
    "scripts/ci/check_poco_ai_native_v1_order_trust_path_iterator.sh",
    "scripts/ci/check_poco_ai_native_v1_order_ordinary_finality_advance.sh",
    "scripts/ci/check_poco_ai_native_v1_weak_subjectivity_renewal.sh",
    "scripts/ci/check_poco_ai_native_v1_cross_version_activation_proof.py",
    "scripts/ci/check_poco_ai_native_v1_cross_version_activation_proof.sh",
    "scripts/ci/check_poco_ai_native_v1_upgrade_kernel.py",
    "scripts/ci/check_poco_ai_native_v1_upgrade_kernel.sh",
    "scripts/ci/check_poco_ai_native_v1_global_execution_binding.py",
    "scripts/ci/check_trnm_poco_da_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_agent_market_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_verify_challenge_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_mvcc_fee_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_consumption_settlement_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_cross_plane_readback_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_cross_plane_checkpoint_v1_boundary.sh",
    "scripts/ci/check_trnm_poco_order_state_v1_boundary.sh",
    "trillionnium/crates/trnm-poco-order-finality-verifier-v1/Cargo.toml",
    "trillionnium/crates/trnm-poco-order-finality-verifier-v1/README.md",
    "trillionnium/crates/trnm-poco-order-finality-verifier-v1/src/lib.rs",
    "trillionnium/crates/trnm-poco-order-state-v1/Cargo.toml",
    "trillionnium/crates/trnm-poco-order-state-v1/README.md",
    "trillionnium/crates/trnm-poco-order-state-v1/src/error.rs",
    "trillionnium/crates/trnm-poco-order-state-v1/src/lib.rs",
    "trillionnium/crates/trnm-poco-order-state-v1/src/store.rs",
    "trillionnium/crates/trnm-poco-order-state-v1/src/tests.rs",
    "trillionnium/crates/trnm-poco-node/src/cross_plane_checkpoint_v1.rs",
]
expected_manifest_paths = {
    "status_path": "docs/protocol/poco-ai-native-v1/status.toml",
    "parameters_path": "docs/protocol/poco-ai-native-v1/parameters.toml",
    "stack_profile_path": "docs/protocol/poco-ai-native-v1/profiles/stack-reference-shadow.toml",
    "verification_registry_path": "docs/protocol/poco-ai-native-v1/profiles/verification-registry-reference.toml",
    "schema_readme_path": "docs/protocol/poco-ai-native-v1/schema/README.md",
    "object_catalog_path": "docs/protocol/poco-ai-native-v1/schema/object-catalog-v1.toml",
    "vectors_readme_path": "docs/protocol/poco-ai-native-v1/vectors/README.md",
    "order_trust_path_schema_path": "docs/protocol/poco-ai-native-v1/schema/cev1-order-trust-path-iterator-v1.json",
    "order_trust_path_vectors_path": "docs/protocol/poco-ai-native-v1/vectors/cev1-order-trust-path-iterator-v1.json",
    "order_trust_path_gate_path": "scripts/ci/check_poco_ai_native_v1_order_trust_path_iterator.sh",
    "ordinary_finality_advance_schema_path": "docs/protocol/poco-ai-native-v1/schema/cev1-order-ordinary-finality-advance-v1.json",
    "ordinary_finality_advance_vectors_path": "docs/protocol/poco-ai-native-v1/vectors/cev1-order-ordinary-finality-advance-v1.json",
    "ordinary_finality_advance_gate_path": "scripts/ci/check_poco_ai_native_v1_order_ordinary_finality_advance.sh",
    "weak_subjectivity_renewal_schema_path": "docs/protocol/poco-ai-native-v1/schema/cev1-weak-subjectivity-checkpoint-renewal-v1.json",
    "weak_subjectivity_renewal_vectors_path": "docs/protocol/poco-ai-native-v1/vectors/cev1-weak-subjectivity-checkpoint-renewal-v1.json",
    "weak_subjectivity_renewal_gate_path": "scripts/ci/check_poco_ai_native_v1_weak_subjectivity_renewal.sh",
    "gap_register_path": "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md",
    "production_contracts_path": "docs/architecture/TRNM_POCO_AI_NATIVE_V1_PRODUCTION_CONTRACTS.md",
    "delivery_plan_path": "docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md",
    "formal_plan_path": "formal/quint/poco-ai-native-v1/README.md",
    "transport_schema_boundary_path": "proto/trnm/poco/ai/v1/README.md",
}
for key, expected_value in expected_manifest_paths.items():
    expect(manifest, "manifest", key, expected_value)
expect(manifest, "manifest", "order_trust_path_negative_cases", 63)
expect(manifest, "manifest", "ordinary_finality_advance_negative_cases", 52)
expect(manifest, "manifest", "weak_subjectivity_renewal_negative_cases", 45)
expect(manifest, "manifest", "required_files", expected_manifest_files)
expect(
    manifest,
    "manifest",
    "draft_candidate_normative_files",
    expected_manifest_files[0:11],
)
expect(manifest, "manifest", "plane_ids", plane_ids)
expect(
    manifest,
    "manifest",
    "reference_profile_ids",
    ["stack-reference-shadow", "verification-registry-reference"],
)
for relative in expected_manifest_files:
    if not (root / relative).is_file():
        issues.append(f"manifest required file is absent: {relative}")

parameters = documents["parameters"]
expect_keys(parameters, "parameters", {
    "schema_version", "parameter_set_id", "protocol_id", "protocol_major",
    "status", "normative_values_frozen", "implemented", "activation",
    "current_implementation_baseline", "order", "data_availability",
    "execution", "finality", "versioning",
})
for key, expected_value in {
    "schema_version": 1,
    "parameter_set_id": "trnm-poco-ai-native-v1-draft-parameters-v1",
    "protocol_id": protocol_id,
    "protocol_major": 1,
    "status": "draft-design-only",
    "normative_values_frozen": False,
    "implemented": False,
    "activation": False,
    "current_implementation_baseline": baseline,
}.items():
    expect(parameters, "parameters", key, expected_value)
order = expect_table(parameters, "parameters", "order")
expect_keys(order, "parameters.order", {
    "safety_kernel", "new_bft_safety_theorem", "quorum_rule",
    "finality_rule", "proposal_unit",
    "deterministic_coordination_execution_before_vote",
    "ai_inference_in_consensus",
})
expect(order, "parameters.order", "safety_kernel", "weighted-chained-hotstuff-derived")
expect(order, "parameters.order", "new_bft_safety_theorem", False)
expect(order, "parameters.order", "quorum_rule", "floor(2*total_weight/3)+1")
expect(order, "parameters.order", "finality_rule", "three-chain")
expect(order, "parameters.order", "ai_inference_in_consensus", False)
availability = expect_table(parameters, "parameters", "data_availability")
expect_keys(availability, "parameters.data_availability", {
    "availability_certificate_required", "durable_store_before_availability_sign",
    "bounded_worker_queues_required", "retrieval_and_repair_required",
    "withholding_challenge_required", "erasure_coding_required",
    "data_availability_sampling_required",
})
expect(availability, "parameters.data_availability", "availability_certificate_required", True)
expect(availability, "parameters.data_availability", "durable_store_before_availability_sign", True)
finality = expect_table(parameters, "parameters", "finality")
expect_keys(finality, "parameters.finality", {
    "order_finality_and_ai_settlement_finality_separated",
    "challenge_may_revert_ordered_blocks", "forward_compensation_and_slashing_only",
})
expect(
    finality,
    "parameters.finality",
    "order_finality_and_ai_settlement_finality_separated",
    True,
)
expect(finality, "parameters.finality", "challenge_may_revert_ordered_blocks", False)
versioning = expect_table(parameters, "parameters", "versioning")
expect_keys(versioning, "parameters.versioning", {
    "wire_version_frozen", "storage_version_frozen",
    "light_client_contract_frozen", "upgrade_contract_frozen",
})
for key in (
    "wire_version_frozen",
    "storage_version_frozen",
    "light_client_contract_frozen",
    "upgrade_contract_frozen",
):
    expect(versioning, "parameters.versioning", key, False)

stack_profile = documents["stack_profile"]
expect_keys(stack_profile, "stack_profile", {
    "schema_version", "profile_id", "protocol_id", "protocol_major", "status",
    "reference_only", "normative", "implemented", "activation",
    "production_candidate", "performance_evidence",
    "current_implementation_baseline", "plane_ids", "order",
    "data_availability", "benchmark_targets",
})
for key, expected_value in {
    "schema_version": 1,
    "profile_id": "stack-reference-shadow",
    "protocol_id": protocol_id,
    "protocol_major": 1,
    "status": "reference-shadow",
    "reference_only": True,
    "normative": False,
    "implemented": False,
    "activation": False,
    "production_candidate": False,
    "performance_evidence": False,
    "current_implementation_baseline": baseline,
    "plane_ids": plane_ids,
}.items():
    expect(stack_profile, "stack_profile", key, expected_value)
stack_order = expect_table(stack_profile, "stack_profile", "order")
expect_keys(stack_order, "stack_profile.order", {
    "safety_kernel", "proposal_unit", "validator_count_target",
    "region_count_target", "new_bft_safety_theorem",
})
expect(stack_order, "stack_profile.order", "safety_kernel", "weighted-chained-hotstuff-derived")
expect(stack_order, "stack_profile.order", "new_bft_safety_theorem", False)
benchmark_targets = expect_table(stack_profile, "stack_profile", "benchmark_targets")
stack_da = expect_table(stack_profile, "stack_profile", "data_availability")
expect_keys(stack_da, "stack_profile.data_availability", {
    "worker_count_per_validator_target", "durable_store_before_sign",
    "full_replication_first", "erasure_coding_active",
    "data_availability_sampling_active",
})
expect_keys(benchmark_targets, "stack_profile.benchmark_targets", {
    "simple_transfer_committed_goodput_tps_min",
    "ai_task_settlement_committed_goodput_tps_min",
    "p99_finality_milliseconds_max", "clean_run_hours_min", "measured",
})
expect(benchmark_targets, "stack_profile.benchmark_targets", "measured", False)

verification_registry = documents["verification_registry"]
expect_keys(verification_registry, "verification_registry", {
    "schema_version", "profile_id", "protocol_id", "protocol_major", "status",
    "normative", "implemented", "activation", "production_candidate",
    "verification_profiles",
})
for key, expected_value in {
    "schema_version": 1,
    "profile_id": "verification-registry-reference",
    "protocol_id": protocol_id,
    "protocol_major": 1,
    "status": "reference-design-only",
    "normative": False,
    "implemented": False,
    "activation": False,
    "production_candidate": False,
}.items():
    expect(verification_registry, "verification_registry", key, expected_value)
verification_profiles = verification_registry.get("verification_profiles")
if not isinstance(verification_profiles, list):
    issues.append("verification_registry.verification_profiles must be an array of tables")
    verification_profiles = []
expected_verification_ids = [
    "deterministic-reexecute",
    "reproducible-ml",
    "zk-validity",
    "tee-attested",
    "stake-quorum",
    "optimistic-challenge",
    "subjective-evaluation",
]
actual_verification_ids = [profile.get("id") for profile in verification_profiles]
if actual_verification_ids != expected_verification_ids:
    issues.append(
        f"verification profile ids={actual_verification_ids!r}, "
        f"expected {expected_verification_ids!r}"
    )
for index, profile in enumerate(verification_profiles):
    if not isinstance(profile, dict):
        issues.append(f"verification profile {index} must be a TOML table")
        continue
    label = f"verification_profiles[{index}]"
    expect_keys(profile, label, {
        "id", "class", "status", "implemented", "activation",
        "order_finality_authority", "settlement_finality_authority",
    })
    expect(profile, label, "status", "design-only")
    for key in (
        "implemented",
        "activation",
        "order_finality_authority",
        "settlement_finality_authority",
    ):
        expect(profile, label, key, False)

object_catalog = documents["object_catalog"]
expect_keys(object_catalog, "object_catalog", {
    "schema_version", "catalog_id", "protocol_id", "protocol_major", "status",
    "normative", "implemented", "activation", "objects",
})
for key, expected_value in {
    "schema_version": 1,
    "catalog_id": "trnm-poco-ai-native-v1-object-catalog-v1",
    "protocol_id": protocol_id,
    "protocol_major": 1,
    "status": "draft-design-only",
    "normative": False,
    "implemented": False,
    "activation": False,
}.items():
    expect(object_catalog, "object_catalog", key, expected_value)
objects = object_catalog.get("objects")
if not isinstance(objects, list):
    issues.append("object_catalog.objects must be an array of tables")
    objects = []
expected_object_ids = [
    "AgentIdentityV1",
    "AgentKeyV1",
    "CapabilityGrantV1",
    "CapabilityRevocationOperationV1",
    "SessionKeyGrantV1",
    "NonceLaneStateV1",
    "AgentTransactionV1",
    "TaskOfferV1",
    "BidV1",
    "TaskLeaseV1",
    "EscrowV1",
    "ComputeCheckpointV1",
    "ExecutionReceiptV1",
    "ResultV1",
    "VerificationProfileV1",
    "VerificationClaimV1",
    "ChallengeV1",
    "EvaluationResultV1",
    "ArtifactCommitmentV1",
    "DaCommitteeDescriptorV1",
    "DaBatchEnvelopeV1",
    "DaAttestationV1",
    "AvailabilityCertificateV1",
    "WithholdingEvidenceV1",
    "RetrievalReceiptV1",
    "BatchRefV1",
    "ChainDescriptorV1",
    "StackProfileV1",
    "BlockHeaderV1",
    "OrderProposalV1",
    "VoteV1",
    "QuorumCertificateV1",
    "TimeoutV1",
    "TimeoutCertificateV1",
    "EpochDescriptorV1",
    "EpochHandoffV1",
    "EpochCheckpointV1",
    "TransactionExecutionReceiptV1",
    "ConsumptionReceiptV1",
    "ConsumptionRollupV1",
    "FeeScheduleV1",
    "SettlementIntentV1",
    "SettlementReceiptV1",
    "StateSyncManifestV1",
    "UpgradePlanV1",
    "MigrationReceiptV1",
    "V0ToV1ActivationStatementV1",
    "V0ToV1ActivationCertificateV1",
    "OrderFinalityProofV1",
    "ApplicationStateProofV1",
    "ArtifactAvailabilityProofV1",
    "ResultSettlementFinalityProofV1",
    "GlobalExecutionBindingV1",
]
actual_object_ids = [item.get("id") for item in objects]
if actual_object_ids != expected_object_ids:
    issues.append(
        f"object ids={actual_object_ids!r}, expected {expected_object_ids!r}"
    )
seen_planes: set[str] = set()
for index, item in enumerate(objects):
    if not isinstance(item, dict):
        issues.append(f"object {index} must be a TOML table")
        continue
    label = f"objects[{index}]"
    expect_keys(item, label, {
        "id", "plane", "status", "implemented", "wire_schema_assigned",
        "activation",
    })
    plane = item.get("plane")
    if plane not in plane_ids:
        issues.append(f"{label}.plane={plane!r}, expected one of {plane_ids!r}")
    else:
        seen_planes.add(plane)
    expect(item, label, "status", "design-only")
    expect(item, label, "implemented", False)
    expect(
        item,
        label,
        "wire_schema_assigned",
        item.get("id") == "GlobalExecutionBindingV1",
    )
    expect(item, label, "activation", False)
if seen_planes != set(plane_ids):
    issues.append(
        f"object catalog plane coverage={sorted(seen_planes)!r}, "
        f"expected {sorted(plane_ids)!r}"
    )

schema_readme = pathlib.Path(schema_readme_raw).read_text(encoding="utf-8")
vectors_readme = pathlib.Path(vectors_readme_raw).read_text(encoding="utf-8")
for stale in (
    "5_positive", "144_exact_error", "28_qc_signatures", "32/32",
    "rejects 144 exact-error", "28 strict-Ed25519 QC signatures plus 4 timeout signatures",
):
    if stale in schema_readme or stale in vectors_readme:
        issues.append(f"v1 schema/vector README retains stale light-client summary: {stale}")
for literal in (
    "draft candidate inventory",
    "no frozen global wire schema",
    "non-exhaustive planning inventory",
    "not the accepted-wire",
    "Every catalog entry remains `design-only`",
    "candidate_non_normative",
    "closed_for_listed_types_only=true",
    "wire_schemas_complete=false",
    "cev1-order-finality-light-client-kernel-v1.json",
    "cev1-order-trust-path-iterator-v1.json",
    "cev1-cross-version-activation-proof-kernel-v1.json",
    "cev1-cross-plane-readback-kernel-v1.json",
    "cev1-global-execution-binding-kernel-v1.json",
    "51 exact-error negative controls",
    "positive carrier",
    "ExecutionBindingWriterUnavailable",
    "fields 13 and 14 are forbidden",
    "light_client_spec_complete=false",
):
    if literal not in schema_readme:
        issues.append(f"schema README is missing required boundary: {literal}")
for literal in (
    "one candidate CEV1 foundation/order-kernel corpus exists",
    "v1 conformance corpus remains incomplete",
    "opaque deterministic",
    "PoCO-BFT v0 vectors cannot be relabelled",
    "conformance_vectors_complete=false",
    "bounded strict-Ed25519 order-signature corpus",
    "full crypto interoperability",
    "separate bounded activation corpus",
    "not a complete upgrade contract",
    "not an alternative to the relation kernel",
    "44 exact-error rejection mutants",
    "upgrade_contract_complete=false",
    "bounded same-version",
    "strict-Ed25519 QC signatures, four timeout signatures, and eight role-specific",
    "It rejects 212",
    "0/1/2/3-hop paths",
    "all 116",
    "cev1-cross-plane-readback-kernel-v1.json",
    "does not claim a real five-store Node",
    "cev1-global-execution-binding-kernel-v1.json",
    "six positive controls",
    "51 parser, identity, context",
    "positive carrier",
    "ExecutionBindingWriterUnavailable",
    "light_client_spec_complete=false",
):
    if literal not in vectors_readme:
        issues.append(f"vectors README is missing required boundary: {literal}")

with pathlib.Path(foundation_vectors_raw).open(encoding="utf-8") as source:
    foundation_vectors = json.load(source)
foundation_status = foundation_vectors.get("status", {})
expected_foundation_status = {
    "classification": "candidate_non_normative",
    "closed_for_listed_types_only": True,
    "normative_freeze": False,
    "global_wire_schema_complete": False,
    "semantic_consistency_proven": False,
    "implementation_or_activation_evidence": False,
    "cryptographic_interoperability_evidence": False,
}
if foundation_status != expected_foundation_status:
    issues.append(
        f"foundation vector status={foundation_status!r}, "
        f"expected {expected_foundation_status!r}"
    )
for key, expected_count in {
    "positive_cases": 27,
    "derived_cases": 1,
    "negative_cases": 24,
}.items():
    cases = foundation_vectors.get(key)
    if not isinstance(cases, list) or len(cases) != expected_count:
        issues.append(
            f"foundation vectors {key} count="
            f"{len(cases) if isinstance(cases, list) else None}, "
            f"expected {expected_count}"
        )

if issues:
    print("; ".join(issues), file=sys.stderr)
    raise SystemExit(1)
PY

python3 "$FOUNDATION_CHECKER" --check --self-test-mutants \
  || fail "candidate CEV1 foundation/order-kernel vectors are inconsistent"

bash "$FOUNDATION_INDEPENDENT_GATE" \
  || fail "independent CEV1 foundation/order-kernel parser rejected the corpus"

bash "$ORDER_CRYPTO_GATE" \
  || fail "bounded CEV1 strict-Ed25519 order-signature corpus was rejected"

bash "$ORDER_FINALITY_LIGHT_CLIENT_GATE" \
  || fail "bounded independent CEV1 OrderFinality light-client corpus was rejected"

bash "$ORDER_TRUST_PATH_GATE" \
  || fail "bounded independent CEV1 Order trust-path iterator corpus was rejected"

bash "$ORDINARY_FINALITY_ADVANCE_GATE" \
  || fail "bounded independent CEV1 Ordinary finality advance corpus was rejected"

bash "$WEAK_SUBJECTIVITY_RENEWAL_GATE" \
  || fail "bounded independent weak-subjectivity checkpoint renewal corpus was rejected"

bash "$UPGRADE_GATE" \
  || fail "bounded v0-to-v1 activation-kernel corpus was rejected"

bash "$CROSS_VERSION_ACTIVATION_PROOF_GATE" \
  || fail "bounded cross-version activation-proof corpus was rejected"

python3 "$GLOBAL_EXECUTION_BINDING_CHECKER" \
  || fail "independent tag-50 GlobalExecutionBinding CEV1 corpus was rejected"

if [[ "${1:-}" == "--static-only" ]]; then
  bash "$TRANSACTION_BATCH_DA_GATE" --static-only \
    || fail "static transaction-batch DA candidate boundary was rejected"
  bash "$CROSS_PLANE_CHECKPOINT_GATE" --static-only \
    || fail "static Rust Order verifier / Node checkpoint candidate boundary was rejected"
  bash "$ORDER_STATE_GATE" --static-only \
    || fail "static Order-state writer / finalized membership binding boundary was rejected"
  bash "$GLOBAL_EXECUTION_GATE" --static-only \
    || fail "static manifest-bound global execution / Node candidate-local owner boundary was rejected"
else
  bash "$TRANSACTION_BATCH_DA_GATE" \
    || fail "bounded transaction-batch DA candidate boundary was rejected"

  bash "$AGENT_MARKET_GATE" \
    || fail "bounded Agent/Market candidate boundary was rejected"

  bash "$VERIFY_CHALLENGE_GATE" \
    || fail "bounded Verify/Challenge candidate boundary was rejected"

  bash "$OBJECT_MVCC_FEE_GATE" \
    || fail "bounded object-MVCC/fee candidate boundary was rejected"

  bash "$CONSUMPTION_SETTLEMENT_GATE" \
    || fail "bounded ConsumptionRollup/settlement candidate boundary was rejected"

  bash "$CROSS_PLANE_READBACK_GATE" \
    || fail "bounded cross-plane fresh-readback candidate boundary was rejected"

  bash "$CROSS_PLANE_CHECKPOINT_GATE" \
    || fail "bounded Rust Order verifier / Node checkpoint candidate boundary was rejected"

  bash "$ORDER_STATE_GATE" \
    || fail "bounded Order-state writer / finalized membership binding boundary was rejected"

  bash "$GLOBAL_EXECUTION_GATE" \
    || fail "manifest-bound global execution / Node candidate-local owner boundary was rejected"
fi

if [[ "${1:-}" == "--static-only" ]]; then
  printf 'PoCO AI-native v1 static design-truth gate: PASS\n'
  exit 0
fi

if [[ "${1:-}" == "--emit-artifact-metadata" ]]; then
  python3 - "$STATUS" <<'PY'
import pathlib
import sys
import tomllib

with pathlib.Path(sys.argv[1]).open("rb") as source:
    status = tomllib.load(source)

print(f"artifact_protocol={status['current_implementation_baseline']}")
print(f"poco_ai_v1_design_target={str(status['architecture_status'] == 'adopted').lower()}")
print(f"poco_ai_v1_specification_status={status['specification_status']}")
print(f"poco_ai_v1_implementation_status={status['implementation_status']}")
print(f"poco_ai_v1_node_support={str(status['node_support']).lower()}")
print(f"poco_ai_v1_activation={str(status['protocol_activation']).lower()}")
print(f"poco_ai_v1_production_candidate={str(status['production_candidate']).lower()}")
print(f"poco_ai_v1_release_ready={str(status['release_ready']).lower()}")
PY
  exit 0
fi

[[ $# -eq 0 ]] || fail "unknown argument: $1"

printf '%s\n' \
  'poco_ai_native_v1_draft_status_inventory=passed architecture=adopted specification=draft foundation_order_candidate=checked,non_normative,listed_types_only positive_vectors=27 derived_vectors=1 negative_vectors=24 independent_parser=standard-library,strict,checked order_signature_crypto_candidate=strict-ed25519,4_validators,vote1,distinct_timeout2,qc4,tc4_per_entry_statements,18_negatives,non_normative order_finality_light_client_candidate=fresh-genesis-ordinary-checkpoint-one-handoff,one-skipped-view-tc,raw-cev1,9_positive,212_exact_error_negatives,qc_signatures60,tc_signatures4,handoff_signatures8,dual_role_context_isolation,bounded_one_handoff_trust_progression,arbitrary_length_false,foundation_structural_snapshot,parameter_constraints,fresh_genesis_empty_payload,non_normative order_trust_path_candidate=checked,non_normative,hops0_1_2_3,replay_append2,63_exact_error_negatives,handoff_sidecar_root_negatives3,epoch_start_tc_negatives11,digest_v1_bound_true,complete_handoff_sidecar_root_true,epoch_start_single_skipped_view_tc_true,epoch_start_exact_handoff_safe_parent,no_locked_qc,latest_checkpoint_anchor,qc_signatures88,tc_signatures4,handoff_signatures24,openssl116,raw_embedded_steps,intermediate_state_binding,certified_head_qc_consumed,max_hops3,v0_activation_false,weak_subjectivity_selection_false,arbitrary_length_false,global_light_client_false ordinary_finality_advance_candidate=checked,non_normative,4_positive_controls,2_sequential_advances,52_exact_error_negatives,same_epoch,one_skipped_view_per_advance,qc_signatures40,tc_signatures8,openssl48,payload_execution_false,arbitrary_history_false,global_light_client_false weak_subjectivity_renewal_candidate=checked,non_normative,exact_three_hop,2_positive_controls,45_exact_error_negatives,first_latest_checkpoint_exact,context_lineage,epoch_age,block_age,validator_set_parameters_roots,strict_monotonicity,same_height_conflict_rejected,operator_auth_false,arbitrary_selection_false,global_light_client_false activation_kernel_candidate=checked,non_normative,1_positive,31_negative,descriptor_hashes_recomputed,dual_weighted_quorum,strict_ed25519_roles,no_fallback cross_version_activation_proof_candidate=checked,non_normative,1_positive,44_exact_error_negative,raw_cev0_field12_exact,frozen_fields13_14_forbidden,separate_cev1_carrier,proposal_signature1,qc_signatures12,openssl13,three_chain,complete_v0_authority_false,migration_false,full_order_proposal_false,upgrade_complete_false transaction_batch_da_candidate=checked,non_normative,transaction_batch_only,durable_before_attest,strict_ed25519,weighted_quorum,retrieval,repair,retention_gc,artifact_false,network_false,node_false,g2_complete_false bounded_formal_candidate=present,3_models,15_invariants,3_witnesses,7_mutants normative_freeze=false global_wire_schema_complete=false global_light_client_spec_complete=false design_only=true semantic_consistency_not_proven=true current_implementation_baseline=poco-bft-v0 implementation=not-implemented node_support=false activation=false production_candidate=false release_ready=false planes=5,design-only global_evidence=all-false order_safety_kernel=weighted-chained-hotstuff-derived new_bft_safety_theorem=false'
printf '%s\n' \
  'transaction_batch_da_hardening=schema_v2,12_positive,20_negative,7_crash_reopen,persistent_attestation_highwater,immutable_durable_manifest,gc_permit_nonconstructible,production_gc_authority_false,external_byte_deletion_false,candidate_only'
printf '%s\n' \
  'agent_market_candidate=schema_v3,13_positive,58_negative,6_crash_reopen,strict_ed25519,controller_lane0,session_nonzero_lanes,shared_budget,exact_scope_enforcement,committed_set_verifier_false,provider_accept_lease_to_task,order_finalized_context_monotonic_cas,durable_finalized_order_block_journal,order_proof_authority_false,task_funded_escrow,bid_one_shot,lease_five_object_atomic,provider_active,exact_replay,durable_state_and_journal_roots,third_state_fence,whole_store_rollback_authority_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'verify_challenge_candidate=schema_v3,16_positive,30_negative,6_crash_reopen,stake_quorum_only,strict_ed25519,unique_verifier_identity_weight,exact_statement_evidence_sequence,required_da_policy_hash_bound,four_registered_verifiers,evidence_cap64,checked_transition_arithmetic,immutable_existing_store_preflight,profile_set_hashes_recomputed,order_finalized_context_monotonic_cas,durable_finalized_order_block_journal,order_proof_authority_false,atomic_evaluation,single_challenge,bond_conservation,durable_state_and_operation_tail_roots,artifact_da_verification_false,other_profiles_false,settlement_false,whole_store_rollback_authority_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'object_mvcc_fee_candidate=schema_v1,12_positive,39_negative,6_crash_reopen,typed_versioned_objects,canonical_serial_oracle,deterministic_conflict_retry,success_reverted_out_of_resource_receipts,four_resource_classes,checked_fee_arithmetic,per_transaction_fee_deltas,block_end_sorted_destination_credit,no_global_collector_hotspot,immutable_existing_store_preflight,atomic_state_receipts_resources_fees,real_parallel_workers_false,authenticated_state_tree_false,order_proof_authority_false,node_false,settlement_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'consumption_settlement_candidate=schema_v2,10_positive,56_negative,6_crash_reopen,single_asset_single_result_single_rollup,bilateral_ed25519,gap_free_receipt_chain,checked_cumulative_usage_charge,atomic_complete_rollup_assignment,chain_assigned_challenge_window,caller_amounts_false,checked_conservation,one_shot_atomic_settlement,durable_finalized_order_block_journal,deterministic_journal_replay,agent_da_result_order_mvcc_authority_false,node_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'global_pre_vote_execution_candidate=12_unit,4_compile_fail,certified_complete_da,exact_five_plane_preview,prepared_checkpoint_cas,verified_order_finality_source_apply,durable_finalized_block_journals,normal_build_finalization_owner_issuer_true,source_plane_finalization_apply_true,terminal_facts_cas,order_state_membership_binding_true,order_binding_positive_carrier_issuer_false,node_process_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'cross_plane_fresh_readback_candidate=schema_v1,3_positive,13_negative,2_compile_fail,five_local_stores,double_sampled_fresh_reopen,same_da_head_and_certificate_sqlite_snapshot,typed_id_adapters,same_context_and_order_head,terminal_receipts_match_sampled_store_heads,readback_consistent_candidate_true,real_five_store_fixture_false,order_proof_authority_false,cross_plane_atomic_commit_false,cross_plane_authority_false,whole_node_checkpoint_false,node_private_owner_false,node_process_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'cross_plane_checkpoint_candidate=bounded_rust_order_verifier,15_unit,4_compile_fail,6_finality_verifier_negative_classes,sparse-membership_2_unit_3_negative,execution_binding_claim_7_unit_23_negative,tag50_create_material_1_unit,order_state_writer_11_unit_5_compile_fail,canonical_receipt_claim_projection_true,tag50_machine_schema_6_positive_51_negative_independent_stdlib,strict_cev1,absolute_claim_bound,exact_single_tag50_witness,positive_carrier_issuable_from_typed_writer_receipt,registered_binding_object_true,deterministic_inert_create_material_true,authoritative_binding_writer_true,normal_binding_issuer_true,direct_ordinary_target_true,certified_chain_ordinary_ancestry_true,order_state_membership_binding_true,raw_claim_self_authorizing_false,absolute_trust_proof_bounds_before_hash_decode,max_retained_views_consumed,pinned_fresh_genesis_rooted_direct_bounded_chain,strict_ed25519,checked_weighted_quorum,checkpoint7_tests,3_positive,12_negative,five_store_reconfirm,parallel_order_and_local_co_observation,order_finalized_cross_plane_authority_false,successor_only_cas,mandatory_fresh_source_target,applied_ack_lost_exact_target,immutable_ro_schema_preflight,rw_dev_ino_uid_nlink_size_time_content_recheck_before_pragma_transaction,rollback_journal_header_preflight,sidecars_rejected_before_open,schema_rejection_byte_stable,path_replacement_rejected,node_private,source_atomicity_false,whole_node_authority_false,anti_rollback_false,node_process_false,global_light_client_false,g2_complete_false,candidate_only'
printf '%s\n' \
  'g2_candidate_aggregate=G2A,G2B,G2C,G2D,G2E,G2F,bounded_local_candidate_gates_present,cross_plane_readback_consistent_candidate_true,node_private_checkpoint_candidate_true,order_finalized_cross_plane_authority_false,cross_plane_authority_false,end_to_end_execution_false,whole_node_checkpoint_authority_false,node_false,g2_complete_false,normative_freeze_false,production_candidate_false,activation_false'
