#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE_MANIFEST="$ROOT/trillionnium/Cargo.toml"
CRATE_ROOT="$ROOT/trillionnium/crates/trnm-native-application"
CRATE_MANIFEST="$CRATE_ROOT/Cargo.toml"
NODE_MANIFEST="$ROOT/trillionnium/crates/trnm-poco-node/Cargo.toml"
NODE_SOURCE="$ROOT/trillionnium/crates/trnm-poco-node/src/lib.rs"
NODE_OWNER="$ROOT/trillionnium/crates/trnm-poco-node/src/native_application_owner.rs"
NODE_P_HOST="$ROOT/trillionnium/crates/trnm-poco-node/src/native_proposal_p_host.rs"
NODE_EXTERNAL_CHECKPOINT="$ROOT/trillionnium/crates/trnm-poco-node/src/external_node_checkpoint.rs"

fail() {
  printf 'TRNM native application boundary gate failed: %s\n' "$*" >&2
  exit 1
}

required_files=(
  "$CRATE_MANIFEST"
  "$CRATE_ROOT/src/lib.rs"
  "$CRATE_ROOT/src/application.rs"
  "$CRATE_ROOT/src/artifact.rs"
  "$CRATE_ROOT/src/error.rs"
  "$CRATE_ROOT/src/execution.rs"
  "$CRATE_ROOT/src/primitives.rs"
  "$CRATE_ROOT/src/recovery.rs"
  "$CRATE_ROOT/src/snapshot.rs"
  "$CRATE_ROOT/src/tests.rs"
  "$CRATE_ROOT/src/validator.rs"
  "$NODE_MANIFEST"
  "$NODE_SOURCE"
  "$NODE_OWNER"
  "$NODE_P_HOST"
  "$NODE_EXTERNAL_CHECKPOINT"
)

for required in "${required_files[@]}"; do
  [[ -f "$required" && ! -L "$required" ]] \
    || fail "missing regular file: ${required#$ROOT/}"
done

python3 - \
  "$WORKSPACE_MANIFEST" \
  "$CRATE_MANIFEST" \
  "$CRATE_ROOT" \
  "$NODE_MANIFEST" \
  "$NODE_SOURCE" \
  "$NODE_OWNER" \
  "$NODE_P_HOST" \
  "$NODE_EXTERNAL_CHECKPOINT" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

workspace_path = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
crate_root = pathlib.Path(sys.argv[3])
node_manifest_path = pathlib.Path(sys.argv[4])
node_source_path = pathlib.Path(sys.argv[5])
node_owner_path = pathlib.Path(sys.argv[6])
node_p_host_path = pathlib.Path(sys.argv[7])
node_external_checkpoint_path = pathlib.Path(sys.argv[8])

with workspace_path.open("rb") as source:
    workspace = tomllib.load(source)
with manifest_path.open("rb") as source:
    manifest = tomllib.load(source)
with node_manifest_path.open("rb") as source:
    node_manifest = tomllib.load(source)

issues: list[str] = []
member = "crates/trnm-native-application"
members = workspace.get("workspace", {}).get("members", [])
if not isinstance(members, list) or members.count(member) != 1:
    issues.append("workspace must contain exactly one native application member")

package = manifest.get("package", {})
expected_package = {
    "name": "trnm-native-application",
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
    "lane": "native-application-boundary",
    "protocol": "poco-bft-v0",
    "native_only": True,
    "implementation_status": "boundary-scaffold",
    "default_node_boundary_owner": True,
    "node_application_engine_integration": False,
    "node_process_integration": False,
    "zero_comet_normal_dependency_closure": True,
    "legacy_adapter": False,
    "production_candidate": False,
}
if metadata != expected_metadata:
    issues.append(
        f"package.metadata.trnm={metadata!r}, expected {expected_metadata!r}"
    )

if manifest.get("dependencies") != {}:
    issues.append("boundary scaffold must have an empty normal dependency table")
if manifest.get("dev-dependencies") not in (None, {}):
    issues.append("boundary scaffold must not have dev-dependencies")
if manifest.get("build-dependencies") not in (None, {}):
    issues.append("boundary scaffold must not have build-dependencies")
if manifest.get("features") != {"default": [], "test-support": []}:
    issues.append("boundary scaffold features differ from the closed inventory")

expected_sources = {
    "application.rs",
    "artifact.rs",
    "error.rs",
    "execution.rs",
    "lib.rs",
    "primitives.rs",
    "recovery.rs",
    "snapshot.rs",
    "tests.rs",
    "validator.rs",
}
actual_sources = {path.name for path in (crate_root / "src").glob("*.rs")}
if actual_sources != expected_sources:
    issues.append(
        f"source inventory={sorted(actual_sources)!r}, "
        f"expected {sorted(expected_sources)!r}"
    )

forbidden = re.compile(
    r"cometbft|tendermint|\babci\b|trnm-consensus-app|trnm-node",
    re.IGNORECASE,
)
for path in [manifest_path, *sorted((crate_root / "src").glob("*.rs"))]:
    text = path.read_text(encoding="utf-8")
    match = forbidden.search(text)
    if match:
        issues.append(f"forbidden legacy token {match.group(0)!r} in {path.name}")

lib = (crate_root / "src" / "lib.rs").read_text(encoding="utf-8")
application = (crate_root / "src" / "application.rs").read_text(encoding="utf-8")
artifact = (crate_root / "src" / "artifact.rs").read_text(encoding="utf-8")
for literal in (
    "#![forbid(unsafe_code)]",
    "pub use application::{",
    "pub use recovery::{",
    "pub use snapshot::{",
    "pub use validator::{",
):
    if literal not in lib:
        issues.append(f"lib.rs is missing required literal: {literal}")
for literal in (
    "pub trait NativeApplicationV0",
    "fn initialize(",
    "fn execute_block(",
    "fn commit_block(",
    "fn state_proof(",
    "fn snapshot(",
    "fn recover(",
    "DeterministicallyInvalid",
    "Unavailable",
):
    if literal not in application:
        issues.append(f"application.rs is missing required literal: {literal}")
for literal in (
    "TRNM_NATIVE_EXECUTED_BLOCK_ARTIFACT_V0",
    "NATIVE_EXECUTED_BLOCK_ARTIFACT_VERSION_V0",
    "MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0",
    "encode_native_executed_block_artifact_v0",
    "decode_native_executed_block_artifact_v0",
    "to_be_bytes()",
    "executed_artifact.trailing_bytes",
):
    if literal not in artifact:
        issues.append(f"artifact.rs is missing required literal: {literal}")

expected_node_truth = {
    "native_application_boundary_dependency": True,
    "native_application_owner_scaffold": True,
    "native_application_owner_public_api": False,
    "native_application_owner_production_constructor": False,
    "native_application_finality_permit_integration": False,
    "native_application_recovery_integration": False,
    "native_application_commit_uncertainty_recovery": False,
    "native_application_durable_p_host": True,
    "native_application_durable_p_host_public_api": False,
    "native_application_durable_p_host_production_constructor": False,
    "native_application_durable_p_store_reopen_readback": True,
    "native_application_durable_p_restart_takeover": False,
    "native_application_durable_p_core_callback": True,
    "native_application_core_d_private_carrier": True,
    "native_application_core_d_restart_takeover": False,
    "native_application_safety_c_authority": True,
    "native_application_safety_c_process_positive_fixture": False,
    "native_application_k_checkpoint_facts": True,
    "native_application_k_whole_node_cas": True,
    "native_application_k_whole_node_cas_successor_only": True,
    "native_application_k_whole_node_cas_bounded_integration": True,
    "native_application_k_whole_node_cas_process_positive_fixture": False,
    "native_application_request_signature_released": True,
    "native_application_request_signature_inert_private": True,
    "native_application_request_signature_signing": False,
}
node_truth = node_manifest.get("package", {}).get("metadata", {}).get("trnm", {})
for key, expected in expected_node_truth.items():
    actual = node_truth.get(key)
    if type(actual) is not type(expected) or actual != expected:
        issues.append(f"node metadata {key}={actual!r}, expected {expected!r}")

node_source = node_source_path.read_text(encoding="utf-8")
owner_source = node_owner_path.read_text(encoding="utf-8")
p_host_source = node_p_host_path.read_text(encoding="utf-8")
external_checkpoint_source = node_external_checkpoint_path.read_text(encoding="utf-8")
if re.search(
    r"^[ \t]*pub(?:[ \t]*\([^)]*\))?[ \t]+mod[ \t]+native_application_owner[ \t]*;",
    node_source,
    re.MULTILINE,
):
    issues.append("native application owner module must remain private")
if re.search(
    r"\bpub(?:\s*\([^)]*\))?\s+use\b[^;]*\bnative_application_owner\b",
    node_source,
    re.MULTILINE,
):
    issues.append("native application owner capability types must not be re-exported")
for privacy_probe in (
    "use trnm_poco_node::native_application_owner::PocoNodeNativeApplicationOwnerV0;",
    "use trnm_poco_node::PocoNodeNativeApplicationOwnerV0;",
    "use trnm_poco_node::PocoNodeNativeFinalityPermitV0;",
    "use trnm_poco_node::native_proposal_p_host::PocoNodeNativeProposalPHostV0;",
    "use trnm_poco_node::PocoNodeNativePersistedProposalPV0;",
):
    if privacy_probe not in node_source:
        issues.append(f"Node docs are missing compile-fail privacy probe {privacy_probe!r}")
    fenced = re.compile(
        r"//! ```compile_fail\s*//! " + re.escape(privacy_probe) + r"\s*//! ```",
        re.MULTILINE,
    )
    if fenced.search(node_source) is None:
        issues.append(f"privacy probe {privacy_probe!r} must remain inside a compile_fail fence")
for function in ("new_for_test_v0", "finality_permit_for_test_v0"):
    if re.search(
        r"#\[cfg\(test\)\]\s*fn\s+" + re.escape(function) + r"\s*\(",
        owner_source,
        re.MULTILINE,
    ) is None:
        issues.append(f"{function} must remain immediately cfg(test)-gated")
if re.search(r"\bpub\s+(?:struct|enum)\s+PocoNodeNativeFinalityPermitV0\b", owner_source):
    issues.append("native finality permit must remain private")
for capability in (
    "PocoNodeNativeApplicationOwnerV0",
    "PocoNodeNativePreparedCommitV0",
    "PocoNodeNativeExecutionOutcomeV0",
    "PocoNodeNativeApplicationOwnerStatusV0",
    "PocoNodeNativeApplicationOwnerErrorV0",
):
    if re.search(
        r"\bpub\s+(?:struct|enum)\s+" + re.escape(capability) + r"\b",
        owner_source,
    ):
        issues.append(f"{capability} must remain crate-private")
if re.search(r"\bpub\s+fn\s+commit_block_v0\s*\(", owner_source):
    issues.append("native owner commit entry must remain private")

if re.search(
    r"^[ \t]*pub(?:[ \t]*\([^)]*\))?[ \t]+mod[ \t]+native_proposal_p_host[ \t]*;",
    node_source,
    re.MULTILINE,
):
    issues.append("native proposal-P host module must remain private")
if re.search(
    r"\bpub(?:\s*\([^)]*\))?\s+use\b[^;]*\bnative_proposal_p_host\b",
    node_source,
    re.MULTILINE,
):
    issues.append("native proposal-P capability types must not be re-exported")
for literal in (
    "ClaimedPayloadValidationRequestV0",
    "CoreIssuedValidPermitV0",
    "decode_application_payload_v0_exact",
    "validate_root_bound_regular_body_v0",
    "NativeApplicationV0",
    "SqliteProposalValidationStoreV0",
    "ReservationOutcomeV0::Applied",
    "read_artifact_exact_v0",
    "PocoNodeNativePersistedProposalPV0",
    "parent_authority_complete",
    "seal_valid_and_deliver_core_d_v0",
    "retry_core_d_v0",
    "CoreAcceptedApplicationValidDV0",
    "deliver_core_accepted_v0",
    "persist_safety_c_and_ack_k_v0",
    "retry_ack_k_v0",
    "acknowledge_confirmed_safety_v0",
    "SafetyConfirmedApplicationAckPending",
    "ApplicationAcked",
    "checkpoint_k_whole_node_v0",
    "release_inert_request_signature_v0",
    "PocoNodeNativeInertRequestSignatureV0",
    "Input::StorageAck",
    "#[cfg(test)]\n    fn open_for_test_v0(",
):
    if literal not in p_host_source:
        issues.append(f"native proposal-P host is missing boundary literal {literal!r}")
for literal in (
    "NATIVE_K_SUCCESSOR_CHECKPOINT_CAS_INTEGRATION_V0: bool = true",
    "advance_native_k_whole_node_checkpoint_v0",
    "confirm_node_checkpoint_head_exact_v0",
    "real_native_k_uncertain_whole_node_cas_releases_only_inert_request_signature_v0",
    "error_after_apply_once: Some(ExternalNodeCheckpointStoreErrorV0::Unavailable)",
):
    if literal not in external_checkpoint_source:
        issues.append(f"native K checkpoint coordinator is missing boundary literal {literal!r}")
for forbidden_call in (
    "step_application_sealed_valid_v0(",
    ".deliver_v0(",
    ".acknowledge_v0(",
):
    if forbidden_call in p_host_source:
        issues.append(f"native proposal-P host must not contain authority call {forbidden_call!r}")
for capability in (
    "PocoNodeNativeProposalPHostV0",
    "PocoNodeNativePersistedProposalPV0",
    "PocoNodeNativeProposalPHostStatusV0",
    "PocoNodeNativeProposalPHostErrorV0",
):
    if re.search(r"\bpub\s+(?:struct|enum)\s+" + re.escape(capability) + r"\b", p_host_source):
        issues.append(f"{capability} must remain non-public")

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
    if package.get("name") == "trnm-native-application"
]
if len(matches) != 1:
    raise SystemExit("Cargo metadata must contain exactly one native application package")
package = matches[0]
if package.get("version") != "0.1.0":
    raise SystemExit("Cargo metadata native application version differs")
if package.get("dependencies") != []:
    raise SystemExit("Cargo metadata native application dependency closure is not empty")
PY

printf '%s\n' \
  'trnm_native_application_boundary=passed,scaffold_only,default_node_boundary_owner_true,owner_private_nonconstructible,finality_permit_unwired,recovery_unwired,commit_uncertainty_recovery_false,private_durable_p_host_true,p_store_reopen_readback_true,p_restart_takeover_false,p_core_callback_bounded_true,p_core_d_private_carrier_true,p_core_d_restart_takeover_false,safety_c_authority_true,safety_c_process_positive_fixture_false,k_checkpoint_facts_true,k_whole_node_cas_successor_only_true,k_whole_node_cas_bounded_integration_true,k_whole_node_cas_process_positive_fixture_false,request_signature_released_true,request_signature_inert_private_true,request_signature_signing_false,node_application_engine_integration_false,node_process_integration_false,zero_comet_normal_dependency_closure_true,production_candidate_false'
