#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERIFIER="trillionnium/crates/trnm-poco-order-finality-verifier-v1"
ORDER_STATE="trillionnium/crates/trnm-poco-order-state-v1"
NODE="trillionnium/crates/trnm-poco-node"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
SPEC="docs/protocol/poco-ai-native-v1/spec-manifest.toml"
GAP="docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
DELIVERY="docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md"
READINESS="RELEASE_READINESS.md"
VECTORS="docs/protocol/poco-ai-native-v1/vectors/cev1-order-finality-light-client-kernel-v1.json"
GATE="scripts/ci/check_trnm_poco_cross_plane_checkpoint_v1_boundary.sh"

INVENTORY=(
  trillionnium/Cargo.toml trillionnium/Cargo.lock
  "$VERIFIER/Cargo.toml" "$VERIFIER/README.md" "$VERIFIER/src/lib.rs"
  "$ORDER_STATE/Cargo.toml" "$ORDER_STATE/README.md"
  "$ORDER_STATE/src/error.rs" "$ORDER_STATE/src/lib.rs"
  "$ORDER_STATE/src/store.rs" "$ORDER_STATE/src/tests.rs"
  "$NODE/Cargo.toml" "$NODE/src/lib.rs" "$NODE/src/cross_plane_checkpoint_v1.rs"
  trillionnium/crates/trnm-poco-cross-plane-readback-v1/Cargo.toml
  trillionnium/crates/trnm-poco-cross-plane-readback-v1/src/join.rs
  trillionnium/crates/trnm-poco-cross-plane-readback-v1/src/types.rs
  "$VECTORS" "$STATUS" "$SPEC" "$GAP" "$DELIVERY" "$READINESS" "$GATE"
  scripts/ci/check_trnm_poco_order_state_v1_boundary.sh
  scripts/ci/check_poco_ai_native_v1_design_truth.sh
  scripts/ci/check_poco_bft_v0_ci_truth.sh
  .github/workflows/trnm-poco-bft-v0.yml
)

fail() {
  printf 'PoCO cross-plane checkpoint v1 boundary failed: %s\n' "$*" >&2
  exit 1
}

candidate_index() {
  local path
  for path in "${INVENTORY[@]}"; do
    git cat-file -e ":$path" >/dev/null 2>&1 || fail "candidate index omits $path"
    git diff --quiet -- "$path" || fail "candidate index differs from worktree for $path"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  candidate_index
  printf 'PoCO cross-plane checkpoint v1 candidate index: PASS\n'
  exit 0
fi
[[ $# -eq 0 || ( $# -eq 1 && "$1" == "--static-only" ) ]] || fail "unknown argument"

for path in "${INVENTORY[@]}"; do
  test -s "$path" || fail "missing/nonempty $path"
done

python3 - trillionnium/Cargo.toml "$VERIFIER/Cargo.toml" "$ORDER_STATE/Cargo.toml" \
  "$NODE/Cargo.toml" "$STATUS" "$SPEC" <<'PY'
import pathlib, sys, tomllib
workspace, verifier_manifest, order_state_manifest, node_manifest, status_path, spec_path = [pathlib.Path(v) for v in sys.argv[1:]]
w = tomllib.loads(workspace.read_text())
v = tomllib.loads(verifier_manifest.read_text())
o = tomllib.loads(order_state_manifest.read_text())
n = tomllib.loads(node_manifest.read_text())
s = tomllib.loads(status_path.read_text())
p = tomllib.loads(spec_path.read_text())
assert "crates/trnm-poco-order-finality-verifier-v1" in w["workspace"]["members"]
assert "crates/trnm-poco-order-state-v1" in w["workspace"]["members"]
assert v["package"]["name"] == "trnm-poco-order-finality-verifier-v1"
assert set(v["dependencies"]) == {"ed25519-dalek", "sha2", "trnm-poco-order-types-v1"}
vt = v["package"]["metadata"]["trnm"]
for key in ["raw_cev1_strict_decode", "exact_byte_reencoding", "absolute_input_byte_bounds_before_hash_decode", "max_retained_views_consumed", "strict_ed25519_qc_verification", "checked_weighted_quorum", "application_state_sparse_membership", "execution_binding_claim_strict_cev1", "execution_binding_claim_absolute_input_bound", "execution_binding_claim_distinct_ordered_witnesses", "execution_binding_positive_carrier_defined", "deterministic_execution_binding_create_material", "ordinary_target_supported", "certified_chain_ordinary_ancestry"]:
    assert vt[key] is True
assert vt["registered_execution_binding_state_object"] is True
for key in ["authoritative_execution_binding_state_writer", "canonical_execution_binding_claim_from_writer_receipt", "normal_execution_binding_issuer", "order_state_membership_binding"]:
    assert vt[key] is True
for key in ["raw_execution_binding_claim_self_authorizing", "caller_supplied_trust_self_authorizing", "tc_supported", "epoch_handoff_supported", "global_light_client_complete", "node_authority_integration", "production_candidate", "activation"]:
    assert vt[key] is False
assert o["package"]["name"] == "trnm-poco-order-state-v1"
assert set(o["dependencies"]) == {
    "rusqlite",
    "sha2",
    "trnm-poco-global-execution-v1",
    "trnm-poco-order-application-v1",
    "trnm-poco-order-finality-verifier-v1",
    "trnm-poco-order-types-v1",
}
ot = o["package"]["metadata"]["trnm"]
for key in ["tag50_authoritative_store_local_writer", "canonical_receipt_claim_projection", "normal_execution_binding_issuer", "order_state_membership_binding"]:
    assert ot[key] is True
for key in ["canonical_node_order_state_commissioning", "g2_global_complete", "normative_freeze", "production_candidate", "activation"]:
    assert ot[key] is False
deps = n["dependencies"]
for name in ["borsh", "trnm-poco-cross-plane-readback-v1", "trnm-poco-order-finality-verifier-v1"]:
    assert name in deps
nt = n["package"]["metadata"]["trnm"]
for key in ["poco_ai_v1_bounded_rust_order_verifier", "poco_ai_v1_cross_plane_checkpoint_candidate", "poco_ai_v1_cross_plane_checkpoint_node_private", "poco_ai_v1_cross_plane_checkpoint_immutable_preflight", "poco_ai_v1_cross_plane_checkpoint_rw_identity_recheck", "poco_ai_v1_cross_plane_checkpoint_rollback_journal_header_preflight"]:
    assert nt[key] is True
for key in ["poco_ai_v1_global_light_client", "poco_ai_v1_cross_plane_checkpoint_process_integration", "poco_ai_v1_cross_plane_source_atomicity", "poco_ai_v1_order_finalized_cross_plane_authority", "poco_ai_v1_anti_whole_store_rollback_authority", "poco_ai_v1_g2_global_complete", "production_candidate", "production_consensus_activation"]:
    assert nt[key] is False
e = s["evidence_tranches"]["cross_plane_checkpoint_admission"]
for key in ["bounded_rust_order_verifier", "verifier_local_absolute_input_bounds_before_hash_decode", "committed_max_retained_views_consumed", "independently_pinned_trust_digest", "deterministic_execution_binding_create_material", "ordinary_target_supported", "certified_chain_ordinary_ancestry", "fresh_five_store_rejoin_before_cas", "exact_initial_reconfirmation", "successor_only_checkpoint_cas", "mandatory_fresh_source_readback", "mandatory_fresh_target_readback", "applied_ack_lost_exact_target_recovery", "trust_pin_lineage_stable", "node_private_checkpoint_admission", "distinct_checkpoint_namespace", "immutable_read_only_existing_file_preflight", "rw_file_identity_revalidated_before_pragma_or_transaction", "rollback_journal_header_preflight", "sqlite_sidecars_rejected_before_open", "schema_rejection_byte_stable", "path_replacement_rejected"]:
    assert e[key] is True
assert e["rust_order_verifier_unit_tests_checked"] == 15
assert e["rust_order_verifier_compile_fail_cases_checked"] == 4
assert e["rust_order_verifier_negative_classes_checked"] == 6
for key in ["application_state_sparse_membership", "execution_binding_claim_strict_cev1", "execution_binding_claim_absolute_input_bound", "execution_binding_claim_distinct_ordered_witnesses", "execution_binding_positive_carrier_defined"]:
    assert e[key] is True
assert e["application_state_membership_unit_tests_checked"] == 2
assert e["application_state_membership_negative_controls_checked"] == 3
assert e["execution_binding_claim_unit_tests_checked"] == 7
assert e["execution_binding_claim_negative_controls_checked"] == 23
assert e["execution_binding_create_material_unit_tests_checked"] == 1
assert e["authoritative_order_state_writer_unit_tests_checked"] == 11
assert e["authoritative_order_state_writer_compile_fail_cases_checked"] == 5
assert e["canonical_receipt_claim_projection"] is True
assert e["direct_ordinary_target_unit_tests_checked"] == 1
assert e["registered_execution_binding_state_object"] is True
assert e["execution_binding_vector_terminal_positive_carrier"] is True
for key in ["authoritative_execution_binding_state_writer", "normal_execution_binding_issuer", "order_state_membership_binding"]:
    assert e[key] is True
assert e["checkpoint_unit_tests_checked"] == 7
assert e["checkpoint_positive_controls_checked"] == 3
assert e["checkpoint_negative_controls_checked"] == 12
for key in ["order_finalized_cross_plane_authority", "cross_plane_source_atomicity", "whole_node_checkpoint_integration", "anti_whole_store_rollback_authority", "node_process_integration", "global_light_client_spec_complete", "g2_global_complete", "normative_freeze", "production_candidate", "activation"]:
    assert e[key] is False
required = set(p["required_files"])
for path in [str(verifier_manifest), "trillionnium/crates/trnm-poco-order-finality-verifier-v1/README.md", "trillionnium/crates/trnm-poco-order-finality-verifier-v1/src/lib.rs", str(order_state_manifest), "trillionnium/crates/trnm-poco-order-state-v1/README.md", "trillionnium/crates/trnm-poco-order-state-v1/src/error.rs", "trillionnium/crates/trnm-poco-order-state-v1/src/lib.rs", "trillionnium/crates/trnm-poco-order-state-v1/src/store.rs", "trillionnium/crates/trnm-poco-order-state-v1/src/tests.rs", "scripts/ci/check_trnm_poco_order_state_v1_boundary.sh", "trillionnium/crates/trnm-poco-node/src/cross_plane_checkpoint_v1.rs", "scripts/ci/check_trnm_poco_cross_plane_checkpoint_v1_boundary.sh"]:
    assert path in required
PY

python3 - "$VERIFIER/src/lib.rs" "$ORDER_STATE/src/store.rs" "$NODE/src/lib.rs" "$NODE/src/cross_plane_checkpoint_v1.rs" <<'PY'
import pathlib, sys
verifier, order_state, node_lib, checkpoint = [pathlib.Path(v).read_text() for v in sys.argv[1:]]
for literal in [
    "trust_bundle_cev1.len() <= MAX_TRUST_BUNDLE_INPUT_BYTES_V1",
    "order_finality_proof_cev1.len() <= MAX_ORDER_FINALITY_PROOF_INPUT_BYTES_V1",
    "sha256(trust_bundle_cev1) == pinned_trust_sha256",
    "encoded == raw",
    "verify_strict",
    "weight >= threshold",
    "(3..=16).contains(&proof.chain.len())",
    "trust.parameters.max_retained_views",
    "committed_retained_view_bound_helper_rejects_three_chain_at_two",
    "proof target differs from the committed three-chain position",
    "verify_pinned_direct_order_finality_v1",
    "direct_ordinary_target_retains_only_certified_prefix_ancestry",
    "derive_global_execution_binding_create_material_v1",
    "tag50_create_material_is_deterministic_later_height_data_not_authority",
    "MAX_EXECUTION_BINDING_CLAIM_INPUT_BYTES_V1",
    "EXECUTION_BINDING_CLAIM_DOMAIN_V1",
    "verify_order_state_execution_binding_claim_v1",
    "previous_key.is_none_or(|previous| previous < key)",
    "GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1",
    "GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1",
    "order.proves_strict_ancestor_v1(candidate_height, candidate_block_id)",
    "OrderStateExecutionBindingReceiptProofV1",
    "encode_order_state_execution_binding_claim_from_receipt_v1",
    "verify_order_state_execution_binding_receipt_v1",
    "ExecutionBindingWriterUnavailable",
    "exact_registered_execution_binding_mints_nonforgeable_carrier",
    "writer_receipt_typed_path_generates_exact_claim_and_issues_carrier",
    "writer_receipt_height_root_key_path_and_ancestry_mutants_fail_closed",
    "execution_binding_sparse_path_node_and_side_orientation_mutants_fail_closed",
    "execution_binding_duplicate_unordered_and_unknown_object_keys_fail_closed",
]:
    assert literal in verifier
assert "#[allow(dead_code)]\nmod cross_plane_checkpoint_v1;" in node_lib
for literal in [
    "fresh_join_cross_plane_v1(stores, request)",
    "reconfirmed.projection() == &initial",
    "predecessor.pinned_trust_sha256 == order.pinned_trust_sha256()",
    "checkpoint_store.fresh_load_v1(scope)? == Some(expected_checkpoint.clone())",
    "expected.generation.checked_add(1) == Some(target.generation)",
    "Mandatory fresh read regardless of the reported compare result.",
    "Some(value) if value == target",
    "Some(value) if value == expected_checkpoint",
    "ThirdCheckpointState",
    "trnm_poco_cross_plane_checkpoint_v1",
    "row metadata differs from canonical record",
    "?mode=ro&immutable=1",
    "open_existing_rw_after_immutable_preflight",
    "checkpoint file dev/ino/uid/nlink/size/time/content identity changed",
    "checkpoint SQLite header or rollback-journal mode differs",
    "missing_table_and_wrong_schema_reject_without_changing_database_bytes",
    "path_replacement_after_immutable_preflight_rejects_before_read_write_effects",
    "sqlite_sidecar_rejects_before_open_without_changing_database_bytes",
    "proof-to-state substitution",
]:
    assert literal in checkpoint, literal
assert "pub(crate) fn admit_verified_cross_plane_checkpoint_v1" not in checkpoint
assert "impl Clone for VerifiedCrossPlaneCheckpointV1" not in checkpoint
assert "#[derive(Debug)]\npub(crate) struct VerifiedCrossPlaneCheckpointV1" in checkpoint
assert "#[derive(Debug)]\npub struct VerifiedOrderStateExecutionBindingV1" in verifier
assert "impl Clone for VerifiedOrderStateExecutionBindingV1" not in verifier
assert "registered execution-binding object has no authoritative v1 Order-state writer" not in verifier
for literal in [
    "pub fn verify_later_order_finality_v1(",
    "verify_order_state_execution_binding_receipt_v1(",
    "pub fn bind_verified_order_state_v1(",
]:
    assert literal in order_state
PY

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
index="$tmp/candidate.index"
GIT_INDEX_FILE="$index" git read-tree HEAD
GIT_INDEX_FILE="$index" git add -- "${INVENTORY[@]}"
GIT_INDEX_FILE="$index" "$GATE" --candidate-index-only >/dev/null

if [[ "${1:-}" == "--static-only" ]]; then
  printf 'PASS: PoCO bounded Rust Order verifier + authoritative Order-state writer + execution-binding claim static boundary\n'
  exit 0
fi

cargo metadata --manifest-path trillionnium/Cargo.toml --locked --offline --no-deps --format-version 1 |
  python3 -c 'import json,sys; names={p["name"] for p in json.load(sys.stdin)["packages"]}; assert "trnm-poco-order-finality-verifier-v1" in names'
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-order-finality-verifier-v1
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-order-finality-verifier-v1 --all-targets -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-node cross_plane_checkpoint_v1
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-node --all-targets --no-default-features -- -D warnings

printf 'PASS: PoCO bounded Rust Order verifier + Node-private cross-plane checkpoint v1 boundary\n'
