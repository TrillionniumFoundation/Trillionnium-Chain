#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$ROOT"

STATIC_ONLY=false
case "${1:-}" in
  "") ;;
  --static-only) STATIC_ONLY=true ;;
  *)
    echo "usage: $0 [--static-only]" >&2
    exit 2
    ;;
esac

TYPES="trillionnium/crates/trnm-poco-order-types-v1"
APPLICATION="trillionnium/crates/trnm-poco-order-application-v1"
VERIFIER="trillionnium/crates/trnm-poco-order-finality-verifier-v1"

for path in \
  trillionnium/Cargo.toml \
  "$TYPES/Cargo.toml" \
  "$TYPES/README.md" \
  "$TYPES/src/g2_manifest_v2.rs" \
  "$TYPES/src/lib.rs" \
  "$APPLICATION/Cargo.toml" \
  "$APPLICATION/README.md" \
  "$APPLICATION/src/g2_manifest_v2.rs" \
  "$APPLICATION/src/lib.rs" \
  "$VERIFIER/Cargo.toml" \
  "$VERIFIER/src/lib.rs"
do
  test -s "$path" || {
    echo "FAIL: missing/nonempty $path" >&2
    exit 1
  }
done

python3 - \
  trillionnium/Cargo.toml \
  "$TYPES/Cargo.toml" \
  "$APPLICATION/Cargo.toml" \
  "$VERIFIER/Cargo.toml" \
  "$TYPES/src/g2_manifest_v2.rs" \
  "$TYPES/src/lib.rs" \
  "$APPLICATION/src/g2_manifest_v2.rs" \
  "$APPLICATION/src/lib.rs" \
  "$VERIFIER/src/lib.rs" <<'PY'
import pathlib
import sys
import tomllib

(
    workspace_path,
    types_manifest_path,
    application_manifest_path,
    verifier_manifest_path,
    types_g2_path,
    types_lib_path,
    application_g2_path,
    application_lib_path,
    verifier_lib_path,
) = map(pathlib.Path, sys.argv[1:])

workspace = tomllib.loads(workspace_path.read_text())
types_manifest = tomllib.loads(types_manifest_path.read_text())
application_manifest = tomllib.loads(application_manifest_path.read_text())
verifier_manifest = tomllib.loads(verifier_manifest_path.read_text())
types_g2 = types_g2_path.read_text()
types_lib = types_lib_path.read_text()
application_g2 = application_g2_path.read_text()
application_lib = application_lib_path.read_text()
verifier_lib = verifier_lib_path.read_text()

members = set(workspace["workspace"]["members"])
assert "crates/trnm-poco-order-types-v1" in members
assert "crates/trnm-poco-order-application-v1" in members

assert types_manifest["package"]["name"] == "trnm-poco-order-types-v1"
assert set(types_manifest["dependencies"]) == {"sha2"}
types_truth = types_manifest["package"]["metadata"]["trnm"]
for key in [
    "exact_cev1_block_header",
    "eight_named_order_roots",
    "typed_block_id",
    "typed_certificate_ids",
    "strict_header_vote_qc_decode",
    "exact_byte_reencoding",
]:
    assert types_truth[key] is True, key
for key in [
    "consensus_header_timestamp",
    "node_process_integration",
    "g2_global_complete",
    "normative_freeze",
    "production_candidate",
    "activation",
]:
    assert types_truth[key] is False, key

assert application_manifest["package"]["name"] == "trnm-poco-order-application-v1"
assert set(application_manifest["dependencies"]) == {"sha2", "trnm-poco-order-types-v1"}
assert set(application_manifest["dev-dependencies"]) == {"serde_json"}
application_truth = application_manifest["package"]["metadata"]["trnm"]
for key in [
    "inert_multi_object_state_preview",
    "exact_parent_sparse_jmt",
    "eight_header_roots_derived",
    "noop_preview",
    "system_tag50_create_preview",
    "self_candidate_tag50_rejected",
    "shared_tag50_machine_vector",
]:
    assert application_truth[key] is True, key
for key in [
    "cev0_payload_input",
    "historical_canonical_tx_input",
    "commit_authority",
    "durable_store",
    "node_process_integration",
    "g2_global_complete",
    "normative_freeze",
    "production_candidate",
    "activation",
]:
    assert application_truth[key] is False, key

assert set(verifier_manifest["dependencies"]) == {
    "ed25519-dalek",
    "sha2",
    "trnm-poco-order-types-v1",
}
verifier_truth = verifier_manifest["package"]["metadata"]["trnm"]
assert verifier_truth["shared_order_types_v1_codec"] is True
assert verifier_truth["private_header_vote_qc_codec"] is False

for required in [
    "pub struct BlockHeaderV1",
    "pub batch_refs_root: [u8; 32]",
    "pub protocol_objects_root: [u8; 32]",
    "pub post_state_root: [u8; 32]",
    "pub transaction_execution_receipts_root: [u8; 32]",
    "pub evidence_root: [u8; 32]",
    "pub consumption_rollups_root: [u8; 32]",
    "pub settlement_root: [u8; 32]",
    "pub resource_usage_root: [u8; 32]",
    "typed_hash32!(BlockIdV1);",
    "pub struct QuorumCertificateV1",
    "decode_block_header_prefix_v1",
    "decode_quorum_certificate_prefix_v1",
]:
    assert required in types_lib, required

header_section = types_lib.split("pub struct BlockHeaderV1", 1)[1].split(
    "impl BlockHeaderV1", 1
)[0]
assert "timestamp" not in header_section
for forbidden in ["trnm_poco_node", "trnm_consensus_types", "CanonicalTx"]:
    assert forbidden not in types_lib, forbidden
for required in [
    "pub struct G2ManifestBoundInputV2",
    "pub struct G2InertExecutionPlanV2",
    "pub fn derive_g2_ordered_list_roots_v2",
    "pub fn revalidate_for_input",
]:
    assert required in types_g2, required
for forbidden in ["candidate_block_id", "post_state_root", "receipt_root"]:
    assert forbidden not in types_g2, forbidden

for required in [
    "pub struct PreparedOrderBlockV1",
    "pub fn preview_order_block_v1",
    "pub fn revalidate_prepared_order_block_v1",
    "SelfCandidateBinding",
    "GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1",
    "sparse_state_root",
    "derive_block_id_v1(&header)",
    "SHARED_TAG50_VECTOR_V1",
    "finalized_post_state_root",
]:
    assert required in application_lib, required
for forbidden in [
    "impl Clone for PreparedOrderBlockV1",
    "fn commit(",
    "trnm_poco_node",
    "trnm_consensus_types",
    "CanonicalTx",
    "BlockHeaderV0",
]:
    assert forbidden not in application_lib, forbidden
for required in [
    "pub struct SealedManifestBoundG2OrderBlockV2",
    "pub struct G2FinalizeBindingRequestV2",
    "pub fn seal_manifest_bound_g2_order_block_v2",
    "pub fn revalidate_sealed_manifest_bound_g2_order_block_v2",
    "into_finalize_binding_request_v2",
]:
    assert required in application_g2, required
for forbidden in [
    "impl Clone for SealedManifestBoundG2OrderBlockV2",
    "impl Clone for G2FinalizeBindingRequestV2",
]:
    assert forbidden not in application_g2, forbidden

for forbidden in [
    "struct Header {",
    "struct Vote {",
    "struct QuorumCertificate {",
]:
    assert forbidden not in verifier_lib, forbidden
for required in [
    "decode_block_header_prefix_v1",
    "decode_quorum_certificate_prefix_v1",
    "derive_block_id_v1",
    "derive_quorum_certificate_id_v1",
]:
    assert required in verifier_lib, required
PY

rustfmt --edition 2021 --check \
  "$TYPES/src/g2_manifest_v2.rs" \
  "$TYPES/src/lib.rs" \
  "$APPLICATION/src/g2_manifest_v2.rs" \
  "$APPLICATION/src/lib.rs" \
  "$VERIFIER/src/lib.rs"

if "$STATIC_ONLY"; then
  echo "PoCO AI-native v1 Order types/application static boundary passed"
  exit 0
fi

cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-order-types-v1 \
  -p trnm-poco-order-application-v1 \
  -p trnm-poco-order-finality-verifier-v1
