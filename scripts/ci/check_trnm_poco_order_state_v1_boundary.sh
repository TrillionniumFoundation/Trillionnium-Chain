#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-order-state-v1"
VERIFIER="trillionnium/crates/trnm-poco-order-finality-verifier-v1"
GLOBAL="trillionnium/crates/trnm-poco-global-execution-v1"
APPLICATION="trillionnium/crates/trnm-poco-order-application-v1"
TYPES="trillionnium/crates/trnm-poco-order-types-v1"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
GATE="scripts/ci/check_trnm_poco_order_state_v1_boundary.sh"

INVENTORY=(
  trillionnium/Cargo.toml trillionnium/Cargo.lock
  "$CRATE/Cargo.toml" "$CRATE/README.md"
  "$CRATE/src/canonical.rs" "$CRATE/src/error.rs" "$CRATE/src/lib.rs"
  "$CRATE/src/store.rs" "$CRATE/src/tests.rs"
  "$VERIFIER/Cargo.toml" "$VERIFIER/src/lib.rs"
  "$GLOBAL/Cargo.toml" "$GLOBAL/src/lib.rs" "$GLOBAL/src/store.rs"
  "$APPLICATION/Cargo.toml" "$APPLICATION/src/lib.rs"
  "$TYPES/Cargo.toml" "$TYPES/src/lib.rs"
  "$STATUS"
  "$GATE"
)

fail() {
  printf 'PoCO Order-state v1 boundary failed: %s\n' "$*" >&2
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
  printf 'PoCO Order-state v1 candidate index: PASS\n'
  exit 0
fi
[[ $# -eq 0 || ( $# -eq 1 && "$1" == "--static-only" ) ]] || fail "unknown argument"

for path in "${INVENTORY[@]}"; do
  test -s "$path" || fail "missing/nonempty $path"
done

python3 - trillionnium/Cargo.toml "$CRATE/Cargo.toml" "$VERIFIER/Cargo.toml" \
  "$GLOBAL/Cargo.toml" "$CRATE/src/lib.rs" "$CRATE/src/store.rs" \
  "$CRATE/src/canonical.rs" "$CRATE/src/tests.rs" "$VERIFIER/src/lib.rs" \
  "$GLOBAL/src/store.rs" "$APPLICATION/Cargo.toml" "$APPLICATION/src/lib.rs" \
  "$TYPES/Cargo.toml" "$TYPES/src/lib.rs" "$STATUS" <<'PY'
import pathlib
import re
import sys
import tomllib

(
    workspace_path,
    manifest_path,
    verifier_manifest_path,
    global_manifest_path,
    lib_path,
    store_path,
    canonical_path,
    tests_path,
    verifier_path,
    global_store_path,
    application_manifest_path,
    application_path,
    types_manifest_path,
    types_path,
    status_path,
) = map(pathlib.Path, sys.argv[1:])
workspace = tomllib.loads(workspace_path.read_text())
manifest = tomllib.loads(manifest_path.read_text())
verifier_manifest = tomllib.loads(verifier_manifest_path.read_text())
global_manifest = tomllib.loads(global_manifest_path.read_text())
application_manifest = tomllib.loads(application_manifest_path.read_text())
types_manifest = tomllib.loads(types_manifest_path.read_text())
lib = lib_path.read_text()
store = store_path.read_text()
canonical = canonical_path.read_text()
tests = tests_path.read_text()
verifier = verifier_path.read_text()
global_store = global_store_path.read_text()
application = application_path.read_text()
types = types_path.read_text()
status = tomllib.loads(status_path.read_text())

assert "crates/trnm-poco-order-state-v1" in workspace["workspace"]["members"]
assert "crates/trnm-poco-order-application-v1" in workspace["workspace"]["members"]
assert "crates/trnm-poco-order-types-v1" in workspace["workspace"]["members"]
assert manifest["package"]["name"] == "trnm-poco-order-state-v1"
assert manifest["features"] == {"default": [], "test-support": []}
assert set(manifest["dependencies"]) == {
    "rusqlite",
    "sha2",
    "trnm-poco-global-execution-v1",
    "trnm-poco-order-application-v1",
    "trnm-poco-order-finality-verifier-v1",
    "trnm-poco-order-types-v1",
}
assert set(manifest["dev-dependencies"]) == {
    "tempfile",
    "trnm-poco-order-finality-verifier-v1",
}
assert application_manifest["package"]["name"] == "trnm-poco-order-application-v1"
assert set(application_manifest["dependencies"]) == {
    "sha2",
    "trnm-poco-order-types-v1",
}
assert set(application_manifest["dev-dependencies"]) == {"serde_json"}
assert types_manifest["package"]["name"] == "trnm-poco-order-types-v1"
assert set(types_manifest["dependencies"]) == {"sha2"}
assert "dev-dependencies" not in types_manifest

truth = manifest["package"]["metadata"]["trnm"]
for key in [
    "tag50_authoritative_store_local_writer",
    "exact_parent_sparse_root_required",
    "parent_nonmembership_proved",
    "create_once_object_version_zero",
    "atomic_successor_height_root_history",
    "fresh_reopen_membership_proof",
    "exact_retry",
    "logical_rollback_detection_with_trusted_pin",
    "normal_build_write_permit_issuer",
    "upstream_terminal_owner_permit_api",
    "canonical_receipt_claim_projection",
    "normal_execution_binding_issuer",
    "canonical_recovered_parent_manifest_bound_g2_seal",
    "order_state_membership_binding",
]:
    assert truth[key] is True, key
for key in [
    "normal_build_raw_bytes_issuer",
    "canonical_node_order_state_commissioning",
    "coherent_whole_file_rollback_authority",
    "g2_global_complete",
    "normative_freeze",
    "production_candidate",
    "activation",
]:
    assert truth[key] is False, key

checkpoint_evidence = status["evidence_tranches"]["cross_plane_checkpoint_admission"]
assert checkpoint_evidence["canonical_recovered_parent_manifest_bound_g2_seal"] is True

verifier_truth = verifier_manifest["package"]["metadata"]["trnm"]
for key in [
    "registered_execution_binding_state_object",
    "authoritative_execution_binding_state_writer",
    "canonical_execution_binding_claim_from_writer_receipt",
    "normal_execution_binding_issuer",
    "order_state_membership_binding",
]:
    assert verifier_truth[key] is True, key
assert verifier_truth["raw_execution_binding_claim_self_authorizing"] is False
assert global_manifest["package"]["metadata"]["trnm"]["normal_build_finalization_owner_issuer"] is True

for token in [
    "pub struct OrderStateWritePermitV1",
    "pub struct MaterializedOrderStateOwnerV1",
    "pub struct OrderStateWriteReceiptV1",
    "pub struct OrderStateMembershipProofV1",
    "pub fn issue_order_state_write_permit_v1(",
    "pub fn materialize_global_execution_binding_v1(",
    "pub fn verify_later_order_finality_v1(",
    "verify_order_state_execution_binding_receipt_v1(",
    "OrderStateExecutionBindingReceiptProofV1",
    "pub fn bind_verified_order_state_v1(",
    "derive_order_binding_create_material_v1(target_height)",
    "prove_from_audit(&audited, height, state_key)",
    "verify_order_state_membership_proof_v1(&proof)",
    "UPDATE order_state_metadata_v1 SET head_height=?1,head_root=?2,head_checksum=?3",
]:
    assert token in store, token

for token in [
    "pub struct OrderStateExecutionBindingReceiptProofV1",
    "pub fn encode_order_state_execution_binding_claim_from_receipt_v1(",
    "pub fn verify_order_state_execution_binding_receipt_v1(",
    "pub fn verify_order_state_execution_binding_claim_v1(",
    "receipt.materialized_height == order.finalized_height",
    "receipt.materialized_state_root == order.finalized_post_state_root",
    "membership.state_key() == receipt.state_key",
    "order.proves_strict_ancestor_v1(candidate_height, candidate_block_id)",
    "siblings.len() == STATE_TREE_SIBLING_COUNT_V1",
    "ExecutionBindingWriterUnavailable",
]:
    assert token in verifier, token
assert "registered execution-binding object has no authoritative v1 Order-state writer" not in verifier

for token in [
    "commitment.candidate_height() != binding.candidate_height()",
    "commitment.candidate_block_id().0 != binding.candidate_block_id()",
    "commitment.candidate_composite_root().0 != binding.candidate_composite_root()",
    "commitment.final_execution_root().0 != binding.final_execution_root()",
]:
    assert token in global_store, token

for token in [
    "typed_hash32!(BlockIdV1);",
    "pub struct BlockHeaderV1",
    "pub enum ParentBlockRefV1",
    "pub fn derive_block_id_v1(",
    "pub fn decode_block_header_v1(",
]:
    assert token in types, token
assert types.count("```compile_fail") == 2

for token in [
    "pub const GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1: u16 = 50;",
    "pub struct GlobalExecutionBindingInputV1",
    "pub struct PreparedSystemObjectCreateV1",
    "pub struct PreparedOrderBlockV1",
    "pub struct RecoveredOrderApplicationLeafV1",
    "pub struct RecoveredOrderApplicationParentV1",
    "pub fn preview_order_block_v1(",
    "pub fn recover_order_application_parent_v1(",
    "pub fn revalidate_recovered_order_application_parent_v1(",
    "pub fn revalidate_prepared_order_block_v1(",
    "derive_block_id_v1(&header)",
    "recovered_parent_rebuilds_next_height_and_rejects_root_or_sequence_substitution",
]:
    assert token in application, token
assert application.count("```compile_fail") == 8

for token in [
    "pub struct CanonicalOrderStateHeadPinV1",
    "pub struct CanonicalFinalizedOrderApplyPermitV1",
    "pub struct AppliedFinalizedOrderStateOwnerV1",
    "pub struct RecoveredCanonicalOrderApplicationParentV1",
    "pub struct PocoCanonicalOrderStateStoreV1",
    "pub fn recover_order_application_parent_v1(",
    "pub fn preview_next_from_recovered_parent_v1(",
    "pub fn seal_manifest_bound_g2_from_recovered_parent_v2(",
    "seal_manifest_bound_g2_order_block_v2(",
    "revalidate_sealed_manifest_bound_g2_order_block_v2(&sealed)",
    "before.blocks.contains_key(&target_height)",
    "after.blocks.contains_key(&target_height)",
    "sealed.header().parent != ParentBlockRefV1::V1Block(parent.pin.block_id)",
    "pub fn issue_finalized_prepared_order_apply_v1(",
    "pub fn apply_finalized_prepared_order_block_v1(",
    "WholeNodeFinalizationOwnerV1",
    "VerifiedOrderFinalityV1",
    "PreparedOrderBlockV1",
    "revalidate_prepared_order_block_v1(prepared)",
    "verify_order_state_execution_binding_receipt_v1(",
    "owner.bind_verified_order_state_v1(binding)",
    "transaction_with_behavior(TransactionBehavior::Immediate)",
    "decode_block_header_v1(&block.header_cev1)",
    "derive_block_id_v1(&header) != block.block_id",
    "canonical_order_state_blocks_v1",
    "canonical_order_state_deltas_v1",
    "canonical_order_state_leaves_v1",
    "canonical_order_state_metadata_v1",
    "canonical application parent changed during mandatory fresh re-audit",
]:
    assert token in canonical, token
for type_name in [
    "CanonicalFinalizedOrderApplyPermitV1",
    "AppliedFinalizedOrderStateOwnerV1",
    "RecoveredCanonicalOrderApplicationParentV1",
]:
    assert f"impl Clone for {type_name}" not in canonical
recovered_parent_api = canonical.split(
    "impl RecoveredCanonicalOrderApplicationParentV1", 1
)[1].split("enum RecoveredCanonicalOrderApplicationParentInnerV1", 1)[0]
assert "application_parent" not in recovered_parent_api
assert "OrderApplicationParentV1" not in recovered_parent_api

for type_name in [
    "OrderStateWritePermitV1",
    "MaterializedOrderStateOwnerV1",
    "VerifiedMaterializedOrderStateOwnerV1",
]:
    assert f"impl Clone for {type_name}" not in store
assert lib.count("```compile_fail") == 12

expected_tests = {
    "zero_height_anchor_is_rejected_before_file_creation",
    "fresh_create_reopen_membership_and_exact_retry",
    "authoritative_receipt_plus_later_finality_issues_exact_binding_carrier",
    "duplicate_fork_and_stale_parent_fail_closed",
    "precommit_rollback_and_postcommit_response_loss_are_exact",
    "nested_value_and_leaf_projection_tamper_fail_closed",
    "partial_history_row_and_schema_tamper_fail_closed",
    "coherent_logical_rollback_requires_and_rejects_against_trusted_pin",
    "sparse_membership_orientation_mutant_rejects",
    "path_and_store_identity_substitution_fail_closed",
    "no_sidecar_is_accepted_on_reopen",
}
actual_tests = set(re.findall(r"(?m)^fn ([a-z0-9_]+)\(\) \{", tests))
assert actual_tests == expected_tests, (actual_tests, expected_tests)
expected_canonical_tests = {
    "canonical_cas_faults_exact_retry_and_fork_fail_closed",
    "canonical_manifest_bound_g2_seal_uses_fresh_recovered_durable_parent",
    "canonical_parent_recovery_supports_consecutive_application_heights",
    "canonical_parent_recovery_rejects_fork_foreign_store_tamper_and_rollback",
    "canonical_partial_projection_tamper_fails_fresh_reopen",
}
actual_canonical_tests = set(re.findall(
    r"(?m)^    fn (canonical_[a-z0-9_]+)\(\) \{",
    canonical,
))
assert actual_canonical_tests == expected_canonical_tests, (
    actual_canonical_tests,
    expected_canonical_tests,
)
PY

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
index="$tmp/candidate.index"
GIT_INDEX_FILE="$index" git read-tree HEAD
GIT_INDEX_FILE="$index" git add -- "${INVENTORY[@]}"
GIT_INDEX_FILE="$index" "$GATE" --candidate-index-only >/dev/null

if [[ "${1:-}" == "--static-only" ]]; then
  printf 'PASS: PoCO Order-state writer + finalized membership binding v1 static boundary\n'
  exit 0
fi

cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-order-state-v1 --locked --offline

printf 'PASS: PoCO Order-state writer + finalized membership binding v1 boundary\n'
