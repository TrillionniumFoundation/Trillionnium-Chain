#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE_MANIFEST="$ROOT/trillionnium/Cargo.toml"
CRATE_ROOT="$ROOT/trillionnium/crates/trnm-native-application-sqlite"
MANIFEST="$CRATE_ROOT/Cargo.toml"
NODE_MANIFEST="$ROOT/trillionnium/crates/trnm-poco-node/Cargo.toml"
NODE_SOURCE="$ROOT/trillionnium/crates/trnm-poco-node/src/lib.rs"
NODE_P_HOST="$ROOT/trillionnium/crates/trnm-poco-node/src/native_proposal_p_host.rs"

fail() {
  printf 'TRNM native application SQLite boundary gate failed: %s\n' "$*" >&2
  exit 1
}

for required in "$WORKSPACE_MANIFEST" "$MANIFEST" "$NODE_MANIFEST" "$NODE_SOURCE" "$NODE_P_HOST"; do
  [[ -f "$required" ]] || fail "missing ${required#$ROOT/}"
done

python3 - "$WORKSPACE_MANIFEST" "$MANIFEST" "$NODE_MANIFEST" "$CRATE_ROOT" "$NODE_SOURCE" "$NODE_P_HOST" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

workspace_path, manifest_path, node_path, crate_root, node_source_path, node_p_host_path = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

with workspace_path.open("rb") as source:
    workspace = tomllib.load(source)
with manifest_path.open("rb") as source:
    manifest = tomllib.load(source)
with node_path.open("rb") as source:
    node = tomllib.load(source)

if "crates/trnm-native-application-sqlite" not in workspace.get("workspace", {}).get("members", []):
    issues.append("workspace does not include the native validation-store scaffold")

package = manifest.get("package", {})
expected_package = {
    "name": "trnm-native-application-sqlite",
    "version": "0.1.0",
    "edition": "2021",
    "license": "MIT",
    "authors": ["Trillionnium Contributors"],
    "publish": False,
}
for key, expected in expected_package.items():
    actual = package.get(key)
    if type(actual) is not type(expected) or actual != expected:
        issues.append(f"package.{key}={actual!r}, expected {expected!r}")

metadata = package.get("metadata", {}).get("trnm", {})
expected_metadata = {
    "lane": "native-application-validation-store",
    "protocol": "poco-bft-v0",
    "native_only": True,
    "implementation_status": "bounded-core-d-safety-c-k-integration",
    "native_application_v0_implementation": False,
    "validation_journal_schema": 5,
    "validation_journal_schema_auto_migration": False,
    "existing_store_read_only_preflight": True,
    "existing_store_immutable_preflight": True,
    "existing_store_sidecar_recovery": False,
    "durable_execution_artifact_p": True,
    "durable_execution_artifact_complete_bytes": True,
    "durable_execution_artifact_canonical_codec": True,
    "durable_execution_artifact_restart_takeover": False,
    "core_delivery_d_record": True,
    "core_delivery_validation_id_binding": True,
    "core_delivery_public_constructor": False,
    "core_delivery_authority_integration": True,
    "core_delivery_accepts_only_opaque_core_carrier": True,
    "request_bound_safety_c_shaped_readback_contract": True,
    "request_bound_safety_c_shaped_provenance_persisted_in_k": True,
    "request_bound_safety_revision_exact_core_revision": True,
    "terminal_k_checkpoint_facts_capability": True,
    "terminal_k_checkpoint_facts_fresh_reconfirm": True,
    "terminal_k_whole_node_cas_integration": False,
    "safety_confirmation_sealed_authority": True,
    "safety_confirmation_authority_integration": True,
    "committed_application_head_advance": False,
    "node_process_integration": False,
    "complete_crash_recovery": False,
    "durable_replay_sidecar_session": True,
    "durable_replay_sidecar_canonical_job_copy": False,
    "durable_replay_process2_activation": False,
    "durable_replay_process3_rehydrate": False,
    "openat_identity_binding": False,
    "wal_shm_identity_pinning": False,
    "anti_whole_machine_rollback_authority": False,
    "production_candidate": False,
}
if metadata != expected_metadata:
    issues.append(f"package.metadata.trnm={metadata!r}, expected {expected_metadata!r}")

if manifest.get("features") != {"default": [], "test-support": []}:
    issues.append("validation-store must retain empty default and test-support features")
expected_dev_dependencies = {"ed25519-dalek", "trnm-consensus-crypto"}
if set(manifest.get("dev-dependencies", {})) != expected_dev_dependencies:
    issues.append("validation-store test dependencies differ from the closed inventory")
if manifest.get("build-dependencies") not in (None, {}):
    issues.append("validation-store scaffold must not have build-dependencies")

dependencies = manifest.get("dependencies", {})
if set(dependencies) != {
    "rusqlite",
    "sha2",
    "trnm-consensus-core",
    "trnm-consensus-safety-store",
    "trnm-consensus-types",
    "trnm-native-application",
}:
    issues.append(f"unexpected normal dependencies: {sorted(dependencies)!r}")
native_dependency = dependencies.get("trnm-native-application")
if not isinstance(native_dependency, dict) or native_dependency.get("path") != "../trnm-native-application":
    issues.append("native boundary dependency must use the exact sibling path")
core_dependency = dependencies.get("trnm-consensus-core")
if not isinstance(core_dependency, dict) or core_dependency.get("path") != "../trnm-consensus-core":
    issues.append("Core authority dependency must use the exact sibling path")
for dependency_name in (
    "trnm-consensus-safety-store",
    "trnm-consensus-types",
):
    dependency = dependencies.get(dependency_name)
    expected_path = f"../{dependency_name}"
    if not isinstance(dependency, dict) or dependency.get("path") != expected_path:
        issues.append(f"{dependency_name} must use the exact sibling path")
crypto_dependency = manifest.get("dev-dependencies", {}).get("trnm-consensus-crypto")
if not isinstance(crypto_dependency, dict) or crypto_dependency.get("path") != "../trnm-consensus-crypto":
    issues.append("test crypto dependency must use the exact sibling path")

node_dependencies = node.get("dependencies", {})
node_sqlite_dependency = node_dependencies.get("trnm-native-application-sqlite")
if not isinstance(node_sqlite_dependency, dict) or node_sqlite_dependency.get("path") != "../trnm-native-application-sqlite":
    issues.append("default Node must carry the exact normal native SQLite dependency")
node_truth = node.get("package", {}).get("metadata", {}).get("trnm", {})
expected_node_truth = {
    "native_application_durable_p_host": True,
    "native_application_durable_p_host_public_api": False,
    "native_application_durable_p_host_production_constructor": False,
    "native_application_durable_p_store_reopen_readback": True,
    "native_application_durable_p_restart_takeover": False,
    "native_application_durable_p_core_callback": True,
    "native_application_core_d_private_carrier": True,
    "native_application_safety_c_authority": True,
    "native_application_safety_c_process_positive_fixture": False,
    "native_application_k_checkpoint_facts": True,
    "native_application_k_whole_node_cas": True,
    "native_application_finality_permit_integration": False,
    "native_application_recovery_integration": False,
    "native_application_commit_uncertainty_recovery": False,
    "production_candidate": False,
    "production_consensus_activation": False,
}
for key, expected in expected_node_truth.items():
    actual = node_truth.get(key)
    if type(actual) is not type(expected) or actual != expected:
        issues.append(f"node metadata {key}={actual!r}, expected {expected!r}")

node_source = node_source_path.read_text(encoding="utf-8")
node_p_host = node_p_host_path.read_text(encoding="utf-8")
for probe in (
    "use trnm_poco_node::native_proposal_p_host::PocoNodeNativeProposalPHostV0;",
    "use trnm_poco_node::PocoNodeNativePersistedProposalPV0;",
):
    if probe not in node_source:
        issues.append(f"Node docs are missing private-P compile-fail probe {probe!r}")
for literal in (
    "ClaimedPayloadValidationRequestV0",
    "SqliteProposalValidationStoreV0",
    "ReservationOutcomeV0::Applied",
    "read_artifact_exact_v0",
    "seal_valid_and_deliver_core_d_v0",
    "retry_core_d_v0",
    "core_valid_permit: CoreIssuedValidPermitV0",
    "#[cfg(test)]\n    fn open_for_test_v0(",
):
    if literal not in node_p_host:
        issues.append(f"Node private-P host is missing boundary literal {literal!r}")

expected_sources = {"binding.rs", "error.rs", "lib.rs", "store.rs", "tests.rs"}
actual_sources = {path.name for path in (crate_root / "src").glob("*.rs")}
if actual_sources != expected_sources:
    issues.append(f"source inventory={sorted(actual_sources)!r}, expected {sorted(expected_sources)!r}")

forbidden = re.compile(
    r"trnm-consensus-app|trnm-node|tendermint|\babci\b|comet",
    re.IGNORECASE,
)
for path in [manifest_path, *sorted((crate_root / "src").glob("*.rs"))]:
    text = path.read_text(encoding="utf-8")
    match = forbidden.search(text)
    if match:
        issues.append(f"forbidden legacy token {match.group(0)!r} in {path.name}")

lib = (crate_root / "src" / "lib.rs").read_text(encoding="utf-8")
binding = (crate_root / "src" / "binding.rs").read_text(encoding="utf-8")
store = (crate_root / "src" / "store.rs").read_text(encoding="utf-8")
tests = (crate_root / "src" / "tests.rs").read_text(encoding="utf-8")
for literal in (
    "#![forbid(unsafe_code)]",
    "deliberately narrower than an application engine",
    "complete canonical",
    "atomic write and fresh-connection exact artifact readback",
    "execute transactions, advance the committed",
):
    if literal not in lib:
        issues.append(f"lib.rs is missing boundary literal {literal!r}")
for literal in (
    "TRNM_NATIVE_PROPOSAL_VALIDATION_ID_V0",
    "CoreDeliveryConfirmationV0",
    "SafetyConfirmationReadbackV0",
    "UntrustedSafetyConfirmationReadbackV0",
    "RequestBoundSafetyConfirmationV0",
    "parent_commit_id",
    "timestamp_ms",
    "active_validator_set_id",
    "generation",
    "payload_root",
    "post_state_root",
    "receipts_root",
    "evidence_root",
    "pub(crate) fn new(",
    "pub(crate) const fn from_confirmed_authority(",
    "let _forged = CoreDeliveryConfirmationV0::new",
    "let binding = ProposalValidationBindingV0::new(",
    "binding.validation_id(), 1, digest, digest",
):
    if literal not in binding:
        issues.append(f"binding.rs is missing exact-binding literal {literal!r}")
for literal in (
    "TransactionBehavior::Immediate",
    "self.discard_connection_v0();",
    "let connection = open_connection_v0(&self.path)",
    "current == *target",
    "current == *source",
    "uncertain.third_state",
    "minimum_durable_sequence",
    "RollbackDetected",
    "read_file_identity_v0",
    "links: u64",
    "mode: u32",
    "verify_durable_target_fresh_v0",
    "RequestBoundSafetyConfirmationV0::verify_readback",
    "delivered.core_delivery.core_revision()",
    '"deliver.core_delivery_validation_id"',
    "safety_core_delivery_digest BLOB",
    "pub fn inspect_request_bound_safety_closure_exact_v0(",
    "pub struct ConfirmedProposalValidationCheckpointFactsV0",
    "pub fn confirm_proposal_validation_checkpoint_facts_exact_v0(",
    "pub fn reconfirm_proposal_validation_checkpoint_facts_exact_v0(",
    "core_delivery_digest_from_record_v0",
    "pub fn deliver_core_accepted_v0(",
    "CoreAcceptedApplicationValidDV0",
    "pub fn native_valid_transition_context_exact_v0(",
    "pub fn acknowledge_confirmed_safety_v0",
    "confirmed_native_valid_head_exact_v0",
    "pending_sign",
    "SignKind::Vote",
    "const SCHEMA_VERSION_V0: i64 = 5;",
    "Connection::open_with_flags(",
    "OpenFlags::SQLITE_OPEN_READ_ONLY",
    "OpenFlags::SQLITE_OPEN_URI",
    'uri.push_str("?mode=ro&immutable=1")',
    'for suffix in ["-wal", "-shm", "-journal"]',
    "if !created {",
    "SELECT type, name, sql FROM sqlite_master",
    'kind == "trigger"',
    "artifact BLOB NOT NULL",
    "ARTIFACT_DIGEST_DOMAIN_V0",
    "decode_checked_artifact_v0",
    "encode_native_executed_block_artifact_v0",
    "decode_native_executed_block_artifact_v0",
):
    if literal not in store:
        issues.append(f"store.rs is missing fail-closed literal {literal!r}")
for literal in (
    "ack_loss_resolves_only_exact_source_or_target_using_a_fresh_connection",
    "third_state_during_uncertain_commit_permanently_fences_the_handle",
    "file_replacement_hardlink_and_mode_drift_are_rejected",
    "external_sequence_floor_rejects_a_local_rollback",
    "row_tampering_is_detected_on_reopen",
    "opening_with_wrong_scope_is_rejected",
    "safety_confirmation_mismatch_does_not_close_k",
    "persisted_safety_confirmation_tampering_is_detected_on_reopen",
    "self_consistent_safety_delivery_substitution_is_rejected_on_reopen",
    "schema_or_trigger_drift_is_rejected_on_reopen",
    "reservation_rejects_artifact_substitution_before_any_durable_write",
    "artifact_corruption_and_truncation_are_detected_on_reopen",
    "core_delivery_for_another_validation_cannot_cross_replay_into_d",
    "foreign_delivered_token_cannot_enter_k",
    "safety_revision_must_equal_the_exact_core_delivery_revision",
    "third_state_during_uncertain_ack_fences_and_reopen_rejects_it",
    "missing_expected_table_is_rejected_without_recreation",
    "old_schema_marker_is_rejected_without_migration_or_rewrite",
    "existing_sqlite_sidecars_are_rejected_before_sqlite_without_side_effects",
    "reconstruct P after reopen",
    "checkpoint_facts_are_owner_affine_and_global_sequence_fresh",
    "issue fresh K checkpoint facts after reopen",
    "opaque_core_d_real_safety_c_closes_k_without_core_storage_ack_or_signature_release",
):
    if literal not in tests:
        issues.append(f"tests.rs is missing required negative {literal!r}")

if issues:
    for issue in issues:
        print(f"- {issue}", file=sys.stderr)
    raise SystemExit(1)
PY

metadata_file="$(mktemp)"
trap 'rm -f -- "$metadata_file"' EXIT
cargo metadata \
  --manifest-path "$WORKSPACE_MANIFEST" \
  --locked \
  --offline \
  --no-deps \
  --format-version 1 >"$metadata_file" \
  || fail "Cargo metadata could not resolve the locked offline workspace"

python3 - "$metadata_file" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matches = [
    package
    for package in document.get("packages", [])
    if package.get("name") == "trnm-native-application-sqlite"
]
if len(matches) != 1:
    raise SystemExit("Cargo metadata must contain exactly one native validation-store package")
package = matches[0]
if package.get("version") != "0.1.0":
    raise SystemExit("Cargo metadata native validation-store version differs")
dependency_names = {dependency.get("name") for dependency in package.get("dependencies", [])}
if dependency_names != {
    "ed25519-dalek",
    "rusqlite",
    "sha2",
    "trnm-consensus-core",
    "trnm-consensus-crypto",
    "trnm-consensus-safety-store",
    "trnm-consensus-types",
    "trnm-native-application",
}:
    raise SystemExit(f"unexpected metadata dependencies: {sorted(dependency_names)!r}")
PY

printf '%s\n' \
  'trnm_native_application_sqlite_boundary=passed,bounded_core_d_real_safety_c_k_integration,validation_journal_schema_5,no_schema_auto_migration,existing_store_read_only_immutable_preflight_true,existing_store_sidecar_recovery_false,durable_execution_artifact_p_true,durable_execution_artifact_complete_bytes_true,durable_execution_artifact_canonical_codec_true,durable_execution_artifact_restart_takeover_false,default_node_normal_dependency_true,node_private_p_host_true,p_store_reopen_readback_true,p_restart_takeover_false,p_core_callback_bounded_true,p_core_d_private_carrier_true,p_host_public_api_false,p_host_production_constructor_false,core_delivery_d_record_true,core_delivery_validation_id_binding_true,core_delivery_public_constructor_false,core_delivery_opaque_authority_carrier_required_true,request_bound_safety_c_shaped_readback_contract_true,request_bound_safety_c_shaped_provenance_persisted_in_k_true,request_bound_safety_revision_exact_core_revision_true,terminal_k_checkpoint_facts_capability_true,terminal_k_checkpoint_facts_fresh_reconfirm_true,terminal_k_whole_node_cas_integration_true,terminal_k_whole_node_cas_successor_only_true,terminal_k_whole_node_cas_process_positive_fixture_false,safety_confirmation_sealed_authority_true,safety_confirmation_authority_integration_true,native_application_v0_implementation_false,committed_application_head_advance_false,node_process_integration_false,complete_crash_recovery_false,durable_replay_sidecar_session_true,durable_replay_canonical_job_copy_false,durable_replay_process2_activation_false,durable_replay_process3_rehydrate_false,openat_identity_binding_false,wal_shm_identity_pinning_false,anti_whole_machine_rollback_authority_false,production_candidate=false'
