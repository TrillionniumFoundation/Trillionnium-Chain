#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-global-execution-v1"
NODE_CRATE="trillionnium/crates/trnm-poco-node"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
PLAN="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
GAPS="docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
GATE="scripts/ci/check_trnm_poco_global_execution_v1_boundary.sh"

INVENTORY=(
  trillionnium/Cargo.toml trillionnium/Cargo.lock
  "$CRATE/Cargo.toml" "$CRATE/README.md"
  "$CRATE/src/codec.rs" "$CRATE/src/error.rs" "$CRATE/src/lib.rs"
  "$CRATE/src/manifest_bound_v2.rs" "$CRATE/src/store.rs"
  "$CRATE/src/tests.rs" "$CRATE/src/types.rs"
  "$NODE_CRATE/Cargo.toml" "$NODE_CRATE/src/lib.rs" "$NODE_CRATE/src/main.rs"
  "$NODE_CRATE/src/g2_manifest_bound_v2.rs"
  "$NODE_CRATE/src/g2_manifest_bound_process_v2.rs"
  "$NODE_CRATE/src/g2_order_commit_v1.rs"
  "$NODE_CRATE/src/g2_order_commit_v1_real_e2e.rs"
  "$NODE_CRATE/tests/g2_manifest_bound_process_v2.rs"
  trillionnium/crates/trnm-poco-order-types-v1/Cargo.toml
  trillionnium/crates/trnm-poco-order-types-v1/src/g2_manifest_v2.rs
  trillionnium/crates/trnm-poco-order-types-v1/src/lib.rs
  trillionnium/crates/trnm-poco-order-application-v1/Cargo.toml
  trillionnium/crates/trnm-poco-order-application-v1/src/g2_manifest_v2.rs
  trillionnium/crates/trnm-poco-order-application-v1/src/lib.rs
  trillionnium/crates/trnm-poco-order-finality-verifier-v1/Cargo.toml
  trillionnium/crates/trnm-poco-order-finality-verifier-v1/src/lib.rs
  trillionnium/crates/trnm-poco-agent-market-v1/src/lib.rs
  trillionnium/crates/trnm-poco-agent-market-v1/src/store.rs
  trillionnium/crates/trnm-poco-verify-challenge-v1/src/lib.rs
  trillionnium/crates/trnm-poco-verify-challenge-v1/src/store.rs
  trillionnium/crates/trnm-poco-mvcc-fee-v1/src/lib.rs
  trillionnium/crates/trnm-poco-mvcc-fee-v1/src/store.rs
  trillionnium/crates/trnm-poco-consumption-settlement-v1/src/lib.rs
  trillionnium/crates/trnm-poco-consumption-settlement-v1/src/store.rs
  "$STATUS" "$PLAN" "$GAPS" "$GATE"
)

fail() {
  printf 'PoCO global pre-vote execution v1 boundary failed: %s\n' "$*" >&2
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
  printf 'PoCO global pre-vote execution v1 candidate index: PASS\n'
  exit 0
fi
[[ $# -eq 0 || ( $# -eq 1 && "$1" == "--static-only" ) ]] || fail "unknown argument"

for path in "${INVENTORY[@]}"; do
  test -s "$path" || fail "missing/nonempty $path"
done

python3 - trillionnium/Cargo.toml "$CRATE/Cargo.toml" "$NODE_CRATE/Cargo.toml" "$STATUS" \
  "$CRATE/src/error.rs" "$CRATE/src/lib.rs" "$CRATE/src/manifest_bound_v2.rs" "$CRATE/src/store.rs" \
  "$CRATE/src/tests.rs" "$NODE_CRATE/src/lib.rs" "$NODE_CRATE/src/g2_manifest_bound_v2.rs" \
  "$PLAN" "$GAPS" <<'PY'
import pathlib, re, sys, tomllib

(
    workspace_path, manifest_path, node_manifest_path, status_path, error_path,
    lib_path, manifest_v2_path, store_path, tests_path, node_lib_path,
    node_g2_path, plan_path, gaps_path,
) = map(pathlib.Path, sys.argv[1:])
workspace = tomllib.loads(workspace_path.read_text())
manifest = tomllib.loads(manifest_path.read_text())
node_manifest = tomllib.loads(node_manifest_path.read_text())
status = tomllib.loads(status_path.read_text())
errors = error_path.read_text()
lib = lib_path.read_text()
manifest_v2 = manifest_v2_path.read_text()
store = store_path.read_text()
tests = tests_path.read_text()
node_lib = node_lib_path.read_text()
node_g2 = node_g2_path.read_text()
plan = plan_path.read_text()
gaps = gaps_path.read_text()

assert "crates/trnm-poco-global-execution-v1" in workspace["workspace"]["members"]
assert manifest["package"]["name"] == "trnm-poco-global-execution-v1"
assert manifest["features"] == {"default": []}
assert set(manifest["dependencies"]) == {
    "borsh", "rusqlite", "sha2", "trnm-poco-agent-market-v1",
    "trnm-poco-consumption-settlement-v1", "trnm-poco-da-v1",
    "trnm-poco-mvcc-fee-v1", "trnm-poco-order-application-v1",
    "trnm-poco-order-finality-verifier-v1",
    "trnm-poco-order-types-v1", "trnm-poco-verify-challenge-v1",
}
truth = manifest["package"]["metadata"]["trnm"]
for key in [
    "certified_da_complete_retrieval_before_preview", "agent_market_pre_vote_preview",
    "verify_challenge_pre_vote_preview", "mvcc_fee_pre_vote_preview",
    "consumption_settlement_pre_vote_preview", "candidate_composite_root",
    "whole_node_validation_sequence_cas", "whole_node_finalization_cas",
    "terminal_facts_single_transaction", "terminal_checkpoint_history_audit",
    "order_binding_owner_seam", "inert_order_binding_create_material",
    "normal_build_finalization_owner_issuer", "source_plane_finalization_apply",
    "order_state_membership_binding",
]:
    assert truth[key] is True, key
for key in [
    "normative_application_jmt_root", "normative_agent_transaction_wire",
    "order_binding_positive_carrier_issuer",
    "anti_whole_store_rollback_authority",
    "multi_level_speculative_overlay",
    "node_process_integration", "g2_global_complete", "protocol_implementation_complete",
    "normative_freeze", "production_candidate", "activation",
]:
    assert truth[key] is False, key

evidence = status["evidence_tranches"]["global_pre_vote_execution_candidate"]
assert evidence["candidate_runtime_implemented"] is True
assert evidence["scope"] == "single-certified-global-item-preview-validation-source-apply-and-local-terminal-facts-cas"
assert evidence["positive_controls_checked"] == 7
assert evidence["negative_controls_checked"] == 21
assert evidence["compile_fail_cases_checked"] == 4
for key in [
    "whole_node_finalization_cas", "terminal_facts_single_transaction",
    "terminal_checkpoint_history_audit", "order_binding_owner_seam",
    "inert_order_binding_create_material",
    "normal_build_finalization_owner_issuer", "source_plane_finalization_apply",
    "order_state_membership_binding",
]:
    assert evidence[key] is True, key
for key in [
    "normative_application_jmt_root", "normative_agent_transaction_wire",
    "order_binding_positive_carrier_issuer",
    "anti_whole_store_rollback_authority",
    "multi_level_speculative_overlay",
    "order_proof_authority_complete", "node_process_integration", "g2_global_complete",
    "global_wire_schema_complete", "global_conformance_vectors_complete", "normative_freeze",
    "production_candidate", "activation",
]:
    assert evidence[key] is False, key

for token in [
    ".fresh_certified_batch_readback(proposal.batch_id)",
    ".retrieve(proposal.batch_id, 0, total_length)",
    "decode_complete_retrieval_v1(",
    "self.compare_and_advance(&checkpoint, &target)?;",
    "self.load_prepared(observed.body.generation, observed.checksum, &commitment)?",
    "self.compare_and_finalize(",
    "INSERT INTO global_execution_finalized_v1",
    "audit_checkpoint_history(&connection, &record)?;",
    "bind_existing_finalization_owner_to_verified_order_state_v1(",
    "derive_inert_order_binding_create_material_v1(",
    "derive_global_execution_binding_create_material_v1(",
    "VerifiedOrderStateExecutionBindingV1",
    "apply_finalized_candidate_and_issue_owner_v1(",
    "advance_empty_order_finalized_v1(",
    "pub fn recover_prepared_ready_v1(",
    "pub fn recover_finalization_owner_v1(",
    "validate_recovery_order_v1(order, prepared, &self.context)?;",
    "validate_recovered_terminal_sources_v1(",
    ".fresh_certified_batch_readback(prepared.body.da_batch_id)",
    "let da = da_certified.head();",
    "self.load_prepared(checkpoint.body.generation, checkpoint.checksum, commitment)?",
    "self.load_finalized(",
    "self.fence_checkpoint()?;",
]:
    assert token in store, token
assert "RecoveryMismatch" in errors
assert store.count(".preview_before_vote_v1(") == 4
assert store.count("sample_source_cut(sources, &self.context)?") >= 3
assert re.search(r"#\[derive\(Debug\)\]\s*pub struct PreVoteExecutionReadyV1", store)
assert "impl Clone for PreVoteExecutionReadyV1" not in store
assert re.search(r"#\[derive\(Debug\)\]\s*pub struct WholeNodeFinalizationOwnerV1", store)
assert "impl Clone for WholeNodeFinalizationOwnerV1" not in store
assert "impl WholeNodeFinalizationOwnerV1" in store
assert "pub const fn candidate_composite_root(&self) -> Hash32V1" in store
assert "self.commitment.candidate_composite_root()" in store
assert "pub(crate) fn bind_existing_finalization_owner_to_verified_order_state_v1(" in store
assert "owner: WholeNodeFinalizationOwnerV1" in store
assert "binding: VerifiedOrderStateExecutionBindingV1" in store
assert "Ok(owner)" in store
assert not re.search(
    r"bind_existing_finalization_owner_to_verified_order_state_v1\(\s*commitment: WholeNodeFinalExecutionCommitmentV1",
    store,
)
assert lib.count("```compile_fail") == 4

for token in [
    "pub struct ManifestBoundGlobalExecutionBatchV2",
    "pub struct ManifestBoundGlobalExecutionInputV2",
    "pub struct ManifestBoundFivePlanePreviewV2",
    "pub struct G2CandidateLocalFinalizeJoinV2",
    "pub fn preview_five_plane_inert_v2(",
    ".fresh_certified_batch_readback(manifest.da_batch_id)",
    ".retrieve(manifest.da_batch_id, 0, total_length)",
    "normalize_candidate_local_receipts_v2(",
    "G2InertExecutionPlanV2::new(&input, Vec::new(), execution_items)",
    "join_finalize_request_v2(",
    "request.plan_digest() != self.plan_digest",
    "request.ordered_roots() != self.ordered_roots",
    "pub const fn input_id(&self) -> G2ManifestBoundInputIdV2",
    "pub const fn candidate_height(&self) -> u64",
    "pub const fn plan_digest(&self) -> G2ExecutionPlanDigestV2",
    "pub const fn binding_digest(&self) -> [u8; 32]",
    "pub fn from_certified_batch_and_fresh_sources_v2(",
    "let source_cut_digest = sample_source_cut(sources, &context)?.digest;",
]:
    assert token in manifest_v2, token
assert manifest_v2.count(".preview_before_vote_v1(") == 4
batch_section = manifest_v2.split(
    "pub struct ManifestBoundGlobalExecutionBatchV2", 1
)[1].split("impl ManifestBoundGlobalExecutionBatchV2", 1)[0]
assert "candidate_block_id" not in batch_section
for forbidden in [
    "impl Clone for ManifestBoundFivePlanePreviewV2",
    "impl Clone for G2CandidateLocalPreviewBindingV2",
    "impl Clone for G2CandidateLocalFinalizeJoinV2",
    "PreVoteExecutionReadyV1",
    "PocoGlobalExecutionStoreV1",
]:
    assert forbidden not in manifest_v2, forbidden

assert "trnm-poco-global-execution-v1" in node_manifest["dependencies"]
node_truth = node_manifest["package"]["metadata"]["trnm"]
for key in [
    "poco_ai_v1_manifest_bound_candidate_local_owner",
    "poco_ai_v1_manifest_bound_candidate_local_journal",
    "poco_ai_v1_manifest_bound_candidate_local_successor_cas",
    "poco_ai_v1_manifest_bound_candidate_local_external_pin_reopen",
    "poco_ai_v1_manifest_bound_candidate_local_fresh_exact_join_recovery",
    "poco_ai_v1_manifest_bound_candidate_local_owner_retains_live_journal",
    "poco_ai_v1_manifest_bound_candidate_local_owner_fresh_exact_revalidation",
    "poco_ai_v1_manifest_bound_candidate_local_path_hash_separate_connection_toctou_narrowed",
]:
    assert node_truth[key] is True, key
for key in [
    "poco_ai_v1_manifest_bound_candidate_local_journal_only_authority",
    "poco_ai_v1_manifest_bound_candidate_local_descriptor_bound_openat_identity",
    "poco_ai_v1_manifest_bound_candidate_local_same_uid_rename_race_closed",
    "poco_ai_v1_manifest_bound_candidate_local_namespace_identity_and_owner_pinned",
    "poco_ai_v1_anti_whole_store_rollback_authority",
    "poco_ai_v1_g2_global_complete",
]:
    assert node_truth[key] is False, key
for key in [
    "poco_ai_v1_manifest_bound_candidate_local_process_integration",
    "poco_ai_v1_manifest_bound_candidate_local_external_pin_process_persisted",
    "poco_ai_v1_manifest_bound_candidate_local_external_pin_authenticated_process_owner",
]:
    assert node_truth[key] is True, key
assert "#[allow(dead_code)]\nmod g2_manifest_bound_v2;" in node_lib
assert not re.search(r"(?m)^pub(?:\(crate\))?\s+mod\s+g2_manifest_bound_v2\s*;", node_lib)
assert not re.search(r"(?m)^pub(?:\(crate\))?\s+use\s+g2_manifest_bound_v2\b", node_lib)

node_production, node_separator, node_tests = node_g2.partition("#[cfg(test)]\nmod tests")
assert node_separator
assert "use trnm_poco_global_execution_v1::G2CandidateLocalFinalizeJoinV2;" in node_production
assert re.search(
    r"#\[derive\(Debug\)\]\s*"
    r"pub\(crate\) struct PocoNodeG2ManifestBoundCandidateLocalOwnerV2\s*\{\s*"
    r"exact_join: G2CandidateLocalFinalizeJoinV2,\s*"
    r"journal: SqliteG2ManifestBoundJournalV2,\s*"
    r"journal_pin: PocoNodeG2ManifestBoundJournalPinV2,\s*\}",
    node_production,
)
assert "impl Clone" not in node_production
assert "BorshDeserialize" not in node_production
assert node_production.count("exact_join: G2CandidateLocalFinalizeJoinV2") == 2
assert node_production.count("fn consume_exact_finalize_join_v2(") == 1
assert re.search(
    r"pub\(crate\) fn consume_exact_finalize_join_v2\(\s*"
    r"self,\s*exact_join: G2CandidateLocalFinalizeJoinV2,\s*\)\s*"
    r"-> ResultV2<PocoNodeG2ManifestBoundCandidateLocalOwnerV2>",
    node_production,
)
assert "CanonicalJoinSnapshotV2::from_exact_join_v2(&exact_join)?" in node_production
assert node_production.count(
    "CanonicalJoinSnapshotV2::from_exact_join_v2(&exact_join)?"
) == 1
assert "checked_receipt_count_v2(exact_join.receipts().len())?" in node_production
assert "object_length(value)" in node_production
assert "to_writer(&mut writer, value)" in node_production
assert "struct HardLimitedBorshWriterV2" in node_production
snapshot_encoder = node_production.split(
    "fn from_exact_join_v2(exact_join: &G2CandidateLocalFinalizeJoinV2)", 1
)[1].split("fn from_raw_v2", 1)[0]
assert snapshot_encoder.index("checked_receipt_count_v2") < snapshot_encoder.index(
    "encode_borsh_bounded_v2(exact_join.receipts()"
)
assert "require_exact_snapshot_v2(&durable, &candidate)?;" in node_production
assert "owner.revalidate_fresh_exact_v2()?;" in node_production
assert node_production.count("fn revalidate_fresh_exact_v2(") == 1
owner_revalidation = node_production.split(
    "fn revalidate_fresh_exact_v2(&self)", 1
)[1].split("fn require_exact_snapshot_v2", 1)[0]
assert "CanonicalJoinSnapshotV2::from_exact_join_v2(&self.exact_join)?" in owner_revalidation
assert owner_revalidation.count("self.journal.audit_fresh_v2()?") == 2
assert "before_head.pin_v2() == self.journal_pin" in owner_revalidation
assert "after_head.pin_v2() == self.journal_pin" in owner_revalidation
assert "require_exact_snapshot_v2(before_head, &candidate)?" in owner_revalidation
assert "require_exact_snapshot_v2(after_head, &candidate)" in owner_revalidation
for forbidden_escape in [
    "into_journal", "journal_mut", "journal_v2(&self)",
    "snapshot_v2(&self)", "record_v2(&self)", "exact_join_v2(&self)",
]:
    assert forbidden_escape not in owner_revalidation, forbidden_escape
assert "mode=ro&immutable=1" in node_production
assert "TransactionBehavior::Immediate" in node_production
assert "PRAGMA journal_mode=DELETE" in node_production
assert "PRAGMA synchronous=FULL" in node_production
assert "PRAGMA trusted_schema=OFF" in node_production
assert "require_trusted_prefix_v2(" in node_production
assert "records.last() == Some(target)" in node_production
assert "records.last() == Some(expected)" in node_production
assert "ThirdJournalState" in node_production
assert "from_external_trusted_parts_v2(" in node_production
assert "external trusted pin is absent from the complete journal" in node_production
assert "journal dev/ino/uid/nlink/mode/size/time/content identity changed" in node_production
assert "g2_manifest_bound_metadata_v2" in node_production
assert "g2_manifest_bound_history_v2" in node_production
assert not re.search(
    r"(?:snapshot|record|pin|root|digest|bytes)\s*:\s*[^,\n]+\)\s*"
    r"->\s*ResultV2<PocoNodeG2ManifestBoundCandidateLocalOwnerV2>",
    node_production,
    re.I,
)
for forbidden in [
    "ManifestBoundGlobalExecutionInputV2", "G2CandidateLocalPreviewBindingV2",
    "G2FinalizeBindingRequestV2", "G2InertExecutionPlanV2",
    "PocoGlobalExecutionStoreV1", "PreVoteExecutionReadyV1",
    "WholeNodeFinalizationOwnerV1", "VerifiedOrderFinalityV1",
    "trnm_consensus_core", "trnm_consensus_signer_journal",
    "trnm_poco_order_application_v1", "broadcast", "Signer",
    "OutboundMessage", "Core<", ".clone(",
]:
    if forbidden == ".clone(":
        # Data-only records and pins may clone. The owner and exact join may not.
        assert "exact_join.clone(" not in node_production
        assert "PocoNodeG2ManifestBoundCandidateLocalOwnerV2: Clone" not in node_production
    else:
        assert forbidden not in node_production, forbidden
for test_name in [
    "exact_join_receipt_bounds_fail_before_large_allocation",
    "real_public_path_exact_join_reopens_recovers_and_source_change_rejects",
    "exact_join_anchor_cas_reopen_and_recovery_are_linear",
    "exact_join_cas_response_loss_resolves_only_source_or_target",
    "exact_join_foreign_mutants_and_third_state_never_mint_owner",
    "exact_join_torn_schema_identity_and_sidecars_fail_closed",
    "exact_join_external_pin_rejects_database_only_rollback",
    "exact_join_immutable_preflight_rejects_file_replacement",
    "exact_join_raw_record_pin_and_preview_have_no_owner_ingress",
]:
    assert f"fn {test_name}()" in node_tests

node_persistence = status["evidence_tranches"][
    "manifest_bound_candidate_local_node_persistence"
]
assert node_persistence["classification"] == "candidate-non-normative"
for key in [
    "exact_finalize_join_only_owner_ingress",
    "candidate_local_owner_non_clone",
    "complete_canonical_join_snapshot",
    "sqlite_anchor_successor_history",
    "successor_only_compare_and_swap",
    "mandatory_fresh_source_readback",
    "mandatory_fresh_target_readback",
    "immutable_read_only_preflight",
    "read_write_file_identity_recheck",
    "path_hash_separate_connection_toctou_narrowed",
    "external_trusted_pin_required",
    "external_trusted_prefix_response_loss_resolution",
    "external_pin_reopen_executed",
    "fresh_exact_typed_join_recovery_required",
    "fresh_exact_typed_join_recovery_executed",
    "candidate_local_owner_retains_live_journal",
    "candidate_local_owner_fresh_exact_revalidation",
]:
    assert node_persistence[key] is True, key
for key in [
    "snapshot_or_record_owner_issuer",
    "descriptor_bound_openat_identity", "same_uid_rename_race_closed",
    "namespace_identity_and_owner_pinned",
    "journal_only_authority", "whole_node_checkpoint_integration",
    "source_plane_apply", "vote_eligibility", "signing_authority",
    "anti_whole_store_rollback_authority",
    "g2_global_complete", "global_wire_schema_complete",
    "global_conformance_vectors_complete", "normative_freeze",
    "production_candidate", "activation",
]:
    assert node_persistence[key] is False, key
for key in [
    "external_pin_process_persisted",
    "external_pin_authenticated_process_owner",
    "node_process_integration",
    "real_five_source_process_fixture_complete",
    "two_process_response_loss_recovery_executed",
]:
    assert node_persistence[key] is True, key
assert node_persistence["normal_binary_process_integration_tests_checked"] == 7
assert node_persistence["dynamic_negative_classes_checked"] == 5

expected_tests = {
    "pre_vote_missing_da_and_partial_retrieval_fail_closed",
    "pre_vote_trailing_and_multiple_global_item_codecs_fail_closed",
    "pre_vote_agent_signature_nonce_and_version_fail_closed",
    "pre_vote_fee_and_conservation_fail_closed",
    "pre_vote_certified_retrieve_preview_composite_root_and_whole_node_cas_are_linear",
    "pre_vote_source_change_after_anchor_prevents_whole_node_cas",
    "verified_order_finality_drives_recoverable_source_apply_and_terminal_owner",
    "foreign_verified_order_target_cannot_start_source_apply",
}
actual_tests = set(re.findall(
    r"(?m)^fn ((?:pre_vote|verified_order|foreign_verified)_[a-z0-9_]+)\(\)",
    tests,
))
assert actual_tests == expected_tests, (actual_tests, expected_tests)
expected_recovery_tests = {
    "prepared_and_finalized_terminal_owners_recover_only_from_exact_durable_facts",
}
actual_recovery_tests = set(re.findall(
    r"(?m)^fn ((?:prepared_and_finalized)_[a-z0-9_]+)\(\)",
    tests,
))
assert actual_recovery_tests == expected_recovery_tests, (
    actual_recovery_tests,
    expected_recovery_tests,
)
expected_terminal_tests = {
    "whole_node_terminal_facts_cas_is_atomic_reopenable_and_exact_retry",
    "whole_node_terminal_owner_stale_fork_and_plane_root_mutants_fail_closed",
    "whole_node_terminal_commit_faults_resolve_source_or_exact_target",
    "whole_node_terminal_partial_torn_tamper_and_logical_rollback_fail_closed",
}
actual_terminal_tests = set(re.findall(r"(?m)^fn (whole_node_terminal_[a-z0-9_]+)\(\)", tests))
assert actual_terminal_tests == expected_terminal_tests, (actual_terminal_tests, expected_terminal_tests)
for token in [
    "missing certified DA batch", "partial local retrieval", "TrailingByte",
    "MultipleGlobalItems", "bad_signature", "capability_command(1, 0)",
    "capability_command(0, 1)", "task_command(500, 101)", "task_command(400, 1)",
    "CandidateCompositeRootMismatch", "CheckpointStale", "SourceCutMismatch",
    "open_existing(", "fresh reopened target readback",
    "BeforeCommit", "AfterCommitBeforeReturn", "MissingFinalizedRow",
    "MissingHistoryTail", "TamperedFinalizedBytes", "MetadataRollbackWithFutureRows",
    "FinalizationStale", "FinalizationOwnerMismatch",
    "terminal owner derives inert later-height tag-50 bytes",
    "authenticated prepared history reissues exact ready carrier",
    "foreign recovery selector rejects",
    "prepared recovery drives exact source-plane replay/apply",
    "fresh five-plane terminal readback reissues finalized owner",
    "foreign finality cannot recover owner",
    "owner.candidate_composite_root()",
    "recovered_owner.candidate_composite_root()",
    "manifest_bound_v2_five_plane_preview_exactly_joins_order_roots",
    "manifest_bound_v2_source_and_plan_substitution_fail_closed",
]:
    assert token in tests, token

for document in [plan, gaps]:
    assert "candidate_local_runtime_implemented=true" in document
    assert "node_process_integration=false" in document
    assert "candidate_local_whole_node_finalization_cas=true" in document
    assert "g2_global_complete=false" in document
    assert "candidate composite root" in " ".join(document.lower().split())
    assert "G2CandidateLocalFinalizeJoinV2" in document
    assert "freshly regenerated typed join" in document or "newly produced" in document
PY

python3 - \
  "$NODE_CRATE/Cargo.toml" "$NODE_CRATE/src/lib.rs" "$NODE_CRATE/src/main.rs" \
  "$NODE_CRATE/src/g2_manifest_bound_v2.rs" \
  "$NODE_CRATE/src/g2_manifest_bound_process_v2.rs" \
  "$NODE_CRATE/src/g2_order_commit_v1_real_e2e.rs" \
  "$NODE_CRATE/tests/g2_manifest_bound_process_v2.rs" \
  trillionnium/crates/trnm-poco-da-v1/src/store.rs \
  trillionnium/crates/trnm-poco-agent-market-v1/src/store.rs \
  trillionnium/crates/trnm-poco-verify-challenge-v1/src/store.rs \
  trillionnium/crates/trnm-poco-mvcc-fee-v1/src/store.rs \
  trillionnium/crates/trnm-poco-consumption-settlement-v1/src/store.rs <<'PY'
import pathlib, re, sys, tomllib

(
    cargo_path, lib_path, main_path, sink_path, process_path, fixture_path,
    process_test_path,
    da_path, agent_path, verify_path, mvcc_path, settlement_path,
) = map(pathlib.Path, sys.argv[1:])

cargo = tomllib.loads(cargo_path.read_text())
lib = lib_path.read_text()
main = main_path.read_text()
sink = sink_path.read_text()
process = process_path.read_text()
fixture = fixture_path.read_text()
process_test = process_test_path.read_text()
sources = {
    "DA": da_path.read_text(),
    "Agent/Market": agent_path.read_text(),
    "Verify/Challenge": verify_path.read_text(),
    "MVCC/Fee": mvcc_path.read_text(),
    "Consumption/Settlement": settlement_path.read_text(),
}

assert "mod g2_manifest_bound_process_v2;" in lib
assert "pub use g2_manifest_bound_process_v2::{" in lib
for token in [
    "prepare_g2_manifest_bound_candidate_process_v2",
    "run_g2_manifest_bound_candidate_process_v2",
    "PocoNodeG2CandidateProcessManifestV2",
]:
    assert token in lib, token
for token in [
    "prepare_g2_manifest_bound_candidate_process_v2",
    "run_g2_manifest_bound_candidate_process_v2",
]:
    assert token in main, token

assert "prepare-g2-manifest-bound-candidate-v2" in main
assert "run-g2-manifest-bound-candidate-v2" in main
assert main.index("prepare-g2-manifest-bound-candidate-v2") < main.index(
    "production_activation_gate_v0()"
)
assert main.index("run-g2-manifest-bound-candidate-v2") < main.index(
    "production_activation_gate_v0()"
)

issuer = process.split("fn issue_exact_finalize_join_v2(", 1)[1].split(
    "fn open_existing_sources_and_order_v2(", 1
)[0]
issuer_chain = [
    "ManifestBoundGlobalExecutionInputV2::from_certified_batch_and_fresh_sources_v2(",
    ".preview_five_plane_inert_v2(&mut source_set)",
    ".into_order_material_v2()",
    ".recover_order_application_parent_v1(canonical_pin)",
    ".seal_manifest_bound_g2_from_recovered_parent_v2(",
    ".into_finalize_binding_request_v2()",
    ".join_finalize_request_v2(request)",
]
positions = [issuer.index(token) for token in issuer_chain]
assert positions == sorted(positions)

for label, source in sources.items():
    assert "pub fn open_existing(" in source, label
    assert "require_existing_regular_store(" in source, label
for token in [
    "PocoDaStoreV1::open_existing(",
    "PocoAgentMarketStoreV1::open_existing(",
    "VerifyChallengeStoreV1::open_existing(",
    "MvccFeeStoreV1::open_existing(",
    "ConsumptionSettlementStoreV1::open_existing(",
    "PocoCanonicalOrderStateStoreV1::open_existing_pinned(",
]:
    assert token in process, token

run_owner = process.split("fn open_g2_manifest_bound_candidate_process_owner_v2(", 1)[1]
assert run_owner.index("ProcessLifetimeLockV2::open_existing_v2(") < run_owner.index(
    "PocoNodeG2ManifestBoundCandidateLocalStoreV2::open_existing_v2("
)
assert run_owner.index("issue_exact_finalize_join_v2(") < run_owner.index(
    ".consume_exact_finalize_join_v2(exact_join)"
)
for token in [
    "file.try_lock()",
    "predecessor_process_checksum",
    "enum PrepareDurablePrefixV2",
    "PrepareDurablePrefixV2::CompleteAnchors",
    "ExternalProcessPinAuthenticationV2::AnchorOfCurrentUniqueSuccessor",
    "process_pin_store.advance_or_reconcile_v2(",
    "target_t0d.journal_id_v2() == t0d_anchor.journal_id_v2()",
    "target_t0d.scope_v2() == self.body.process_scope",
    "target_t0d.generation_v2() == expected_target_generation",
    "target_t0d.checksum_v2() != t0d_anchor.checksum_v2()",
    "require_identity_content_sha256_v2(",
    ".take(limit).read_to_end(&mut bytes)",
    "revalidate_fresh_before_ready_v2",
    '"READY candidate_only=true',
    "wait_for_control_eof_v2",
]:
    assert token in process, token
assert "thread::park();" not in process

for token in [
    "pub(crate) fn expected_anchor_pin_v2(",
    "pub(crate) fn exact_finalize_join_commitment_v2(",
    "pub(crate) fn revalidate_fresh_anchor_only_v2(&self)",
    "pub(crate) fn revalidate_fresh_exact_v2(&self)",
]:
    assert token in sink, token

process_targets = [target for target in cargo["test"] if target["name"] == "g2_manifest_bound_process_v2"]
assert process_targets == [{
    "name": "g2_manifest_bound_process_v2",
    "path": "tests/g2_manifest_bound_process_v2.rs",
}]
assert cargo["features"]["g2-process-test-support"] == [
    "fixture-raw-key", "dep:tempfile",
]
assert cargo["dependencies"]["tempfile"] == {
    "version": "3", "optional": True,
}
assert '#[cfg(feature = "g2-process-test-support")]' in lib
assert "pub use g2_order_commit_v1::real_e2e_tests::PocoNodeG2ProcessFixtureV2;" in lib
assert "g2-process-test-support" not in main
assert "PocoNodeG2ProcessFixtureV2" not in main

fixture_contract = fixture.split(
    "pub struct PocoNodeG2ProcessFixtureV2", 1
)[1].split("fn canonical_file_identity_v1", 1)[0]
for token in [
    "RealG2RigV1::new()",
    "certify_manifest_bound_batch_v2(&batch, 2)",
    "PocoCanonicalOrderStateStoreV1::initialize_new(",
    "PocoNodeG2CandidateProcessManifestV2 {",
    "agent_market_trust_bundle: rig.agent_config.trust_bundle.clone()",
    "verify_challenge_trust_bundle: rig.verify_config.trust_bundle.clone()",
    "mvcc_fee_genesis: rig.mvcc_genesis.clone()",
    "settlement_config",
    "borsh::to_vec(&manifest)",
]:
    assert token in fixture_contract, token
for forbidden in [
    "G2CandidateLocalFinalizeJoinV2", "consume_exact_finalize_join_v2",
    "PocoNodeG2ManifestBoundCandidateLocalOwnerV2",
    "run_g2_manifest_bound_candidate_process_v2",
]:
    assert forbidden not in fixture_contract, forbidden
for token in [
    'env!("CARGO_BIN_EXE_trnm-poco-node")',
    "Command::new(NODE)",
    "normal_node_default_and_unknown_commands_remain_fail_closed_v2",
    "missing_and_symlink_manifest_fail_before_any_durable_process_state_v2",
    "real_five_source_two_process_response_loss_matrix_v2",
    "PREPARED anchor is not the READY target",
    "spawn_real_run_v2(&fixture, &anchor)",
    "assert_eq!(field_v2(&ready_two, \"process_pin_checksum\"), target_one)",
    "drop(process_two.stdin.take())",
    "real_fixture_drift_temp_and_rollback_subset_fail_before_ready_v2",
]:
    assert token in process_test, token

assert "trnm_poco_lab_validator" not in process
assert not re.search(r"(?m)^use trnm_consensus_core\b", process)
assert not re.search(r"(?m)^use trnm_consensus_signer", process)
assert not re.search(r"(?m)^use .*network", process)
for forbidden in [
    ".execute_order_finalized(", ".execute_block(",
    ".apply_finalized_prepared_order_block_v1(",
    ".advance_empty_order_finalized_v1(", "PocoGlobalExecutionStoreV1",
    "PreVoteExecutionReadyV1", "WholeNodeFinalizationOwnerV1",
]:
    assert forbidden not in process, forbidden

dependencies = cargo["dependencies"]
for dependency in [
    "trnm-poco-da-v1", "trnm-poco-agent-market-v1",
    "trnm-poco-verify-challenge-v1", "trnm-poco-mvcc-fee-v1",
    "trnm-poco-consumption-settlement-v1",
]:
    assert dependency in dependencies, dependency
    assert dependencies[dependency].get("optional") is not True, dependency

truth = cargo["package"]["metadata"]["trnm"]
for key in [
    "poco_ai_v1_manifest_bound_candidate_local_descriptor_bound_openat_identity",
    "poco_ai_v1_manifest_bound_candidate_local_same_uid_rename_race_closed",
    "poco_ai_v1_manifest_bound_candidate_local_namespace_identity_and_owner_pinned",
    "poco_ai_v1_anti_whole_store_rollback_authority",
    "poco_ai_v1_g2_global_complete",
    "production_candidate",
    "production_consensus_activation",
]:
    assert truth[key] is False, key
for key in [
    "poco_ai_v1_manifest_bound_candidate_local_process_integration",
    "poco_ai_v1_manifest_bound_candidate_local_external_pin_process_persisted",
    "poco_ai_v1_manifest_bound_candidate_local_external_pin_authenticated_process_owner",
]:
    assert truth[key] is True, key

print("PASS: normal-build candidate main -> existing-only issuer -> exact T0-D sink static chain")
PY

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
index="$tmp/candidate.index"
GIT_INDEX_FILE="$index" git read-tree HEAD
GIT_INDEX_FILE="$index" git add -- "${INVENTORY[@]}"
GIT_INDEX_FILE="$index" "$GATE" --candidate-index-only >/dev/null

if [[ "${1:-}" == "--static-only" ]]; then
  printf 'PASS: PoCO global pre-vote execution v1 static candidate boundary\n'
  exit 0
fi

cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-global-execution-v1 --locked --offline

cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --lib --locked --offline \
  g2_manifest_bound_v2::tests

printf 'PASS: PoCO global pre-vote execution v1 candidate boundary\n'
