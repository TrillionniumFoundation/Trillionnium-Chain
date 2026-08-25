#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE_MANIFEST="$ROOT/trillionnium/Cargo.toml"
WORKSPACE_LOCK="$ROOT/trillionnium/Cargo.lock"
CRATE_ROOT="$ROOT/trillionnium/crates/trnm-native-execution-v0"
MANIFEST="$CRATE_ROOT/Cargo.toml"
README="$CRATE_ROOT/README.md"
VECTOR="$CRATE_ROOT/vectors/legacy-runtime-jmt-v0.json"
VECTOR_HASH="$VECTOR.sha256"
COMPLETE_VECTOR="$CRATE_ROOT/vectors/native-complete-durable-p-v0.json"
COMPLETE_VECTOR_HASH="$COMPLETE_VECTOR.sha256"
ARCHIVE_MANIFEST="$ROOT/trillionnium/crates/trnm-consensus-app/Cargo.toml"
ARCHIVE_LOCK="$ROOT/trillionnium/crates/trnm-consensus-app/Cargo.lock"
ARCHIVE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-app/src/native_payload_validation.rs"

fail() {
  printf 'TRNM native execution v0 boundary gate failed: %s\n' "$*" >&2
  exit 1
}

for required in \
  "$WORKSPACE_MANIFEST" "$WORKSPACE_LOCK" "$MANIFEST" "$README" \
  "$CRATE_ROOT/src/lib.rs" "$CRATE_ROOT/src/canonical_lab_bootstrap.rs" \
  "$CRATE_ROOT/src/complete.rs" \
  "$CRATE_ROOT/src/durable.rs" "$CRATE_ROOT/src/store.rs" \
  "$CRATE_ROOT/src/tests.rs" \
  "$VECTOR" "$VECTOR_HASH" "$COMPLETE_VECTOR" "$COMPLETE_VECTOR_HASH" \
  "$ARCHIVE_MANIFEST" "$ARCHIVE_LOCK" "$ARCHIVE_SOURCE"; do
  [[ -f "$required" ]] || fail "missing ${required#$ROOT/}"
done

python3 - "$WORKSPACE_MANIFEST" "$WORKSPACE_LOCK" "$MANIFEST" "$README" \
  "$CRATE_ROOT" "$VECTOR" "$VECTOR_HASH" "$COMPLETE_VECTOR" \
  "$COMPLETE_VECTOR_HASH" "$ARCHIVE_MANIFEST" "$ARCHIVE_SOURCE" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import tomllib

(
    workspace_path,
    workspace_lock_path,
    manifest_path,
    readme_path,
    crate_root,
    vector_path,
    vector_hash_path,
    complete_vector_path,
    complete_vector_hash_path,
    archive_manifest_path,
    archive_source_path,
) = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

def load_toml(path: pathlib.Path):
    with path.open("rb") as source:
        return tomllib.load(source)

workspace = load_toml(workspace_path)
manifest = load_toml(manifest_path)
archive_manifest = load_toml(archive_manifest_path)
workspace_lock = load_toml(workspace_lock_path)

members = workspace.get("workspace", {}).get("members", [])
if members.count("crates/trnm-native-execution-v0") != 1:
    issues.append("active workspace must contain the native execution candidate exactly once")
for archived in ("crates/trnm-consensus-app", "crates/trnm-node"):
    if archived not in workspace.get("workspace", {}).get("exclude", []):
        issues.append(f"active workspace no longer excludes archive {archived}")

package = manifest.get("package", {})
expected_package = {
    "name": "trnm-native-execution-v0",
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

expected_metadata = {
    "lane": "poco-bft-v0-native-execution",
    "protocol": "poco-bft-v0",
    "production_authority": False,
    "durable_artifact_p": True,
    "durable_artifact_p_restart_readback": True,
    "deterministic_preview_read_only": True,
    "multi_overlay_durable_p": True,
    "fork_coexistence": True,
    "finalized_prefix_pruning": True,
    "stable_precommit_application_commit_id": True,
    "multi_overlay_restart_readback": True,
    "commit_uncertain_third_state_fenced": True,
    # Crash/WAL recovery facts are part of the closed machine-readable
    # metadata contract.  Keep these in exact lockstep with the manifest;
    # omitting one must fail the gate rather than silently accepting drift.
    "commit_directory_fsync_attempted": True,
    "sigkill_commit_boundary_matrix": True,
    "short_write_reopen_fail_closed": True,
    "automatic_hot_rollback_journal_recovery": True,
    "automatic_wal_recovery": False,
    "h1_state_sync_trusted_base_import": True,
    "h1_state_sync_import_has_no_local_p": True,
    "h1_state_sync_import_restart_readback": True,
    "qc_as_application_commit": False,
    "native_application_v0_implementation": True,
    "full_ordinary_post_state_root": True,
    "system_writes_included": True,
    "core_application_seal_eligible": False,
    "pinned_parent_trust_bundle_proven": True,
    "core_valid_callback": False,
    "safety_authority_integration": False,
    "request_signature_emission": False,
    "signing_or_broadcast": False,
    "whole_node_checkpoint_cas": False,
    "production_candidate": False,
}
metadata = package.get("metadata", {}).get("trnm", {})
if metadata != expected_metadata:
    issues.append(f"package.metadata.trnm={metadata!r}, expected {expected_metadata!r}")

expected_dependencies = {
    "anyhow", "borsh", "fs2", "hex", "ics23", "jmt", "prost", "rusqlite",
    "serde", "serde_json", "sha2", "trnm-consensus-crypto",
    "trnm-consensus-types", "trnm-finality-types", "trnm-native-application",
    "trnm-protocol", "trnm-runtime",
}
if set(manifest.get("dependencies", {})) != expected_dependencies:
    issues.append("native execution normal dependency inventory changed")
if set(manifest.get("dev-dependencies", {})) != {"ed25519-dalek", "tempfile"}:
    issues.append("native execution development dependency inventory changed")

for package_entry in workspace_lock.get("package", []):
    name = package_entry.get("name", "").lower()
    if name in {"trnm-consensus-app", "trnm-node"} or any(
        token in name for token in ("comet", "tendermint", "abci")
    ):
        issues.append(f"active Cargo.lock regained archive dependency {name}")

expected_sources = {
    "auth_tree.rs", "canonical_lab_bootstrap.rs", "complete.rs", "durable.rs", "lib.rs",
    "poco_application.rs", "poco_nullifier.rs", "poco_semantics.rs", "poco_snapshot.rs",
    "poco_transition.rs", "store.rs", "tests.rs", "validator_lifecycle.rs",
}
actual_sources = {path.name for path in (crate_root / "src").glob("*.rs")}
if actual_sources != expected_sources:
    issues.append(f"source inventory={sorted(actual_sources)!r}, expected {sorted(expected_sources)!r}")

for path in [manifest_path, *sorted((crate_root / "src").glob("*.rs"))]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"(?:extern\s+crate|use)\s+(?:trnm_consensus_app|trnm_node|tendermint(?:_abci|_proto)?)\b|"
        r"(?:trnm_consensus_app|trnm_node|tendermint_abci|tendermint_proto)::",
        text,
    )
    if match:
        issues.append(f"active candidate regained legacy token {match.group(0)!r} in {path.name}")

lib = (crate_root / "src" / "lib.rs").read_text(encoding="utf-8")
canonical_lab_bootstrap = (
    crate_root / "src" / "canonical_lab_bootstrap.rs"
).read_text(encoding="utf-8")
complete = (crate_root / "src" / "complete.rs").read_text(encoding="utf-8")
durable = (crate_root / "src" / "durable.rs").read_text(encoding="utf-8")
store = (crate_root / "src" / "store.rs").read_text(encoding="utf-8")
tests = (crate_root / "src" / "tests.rs").read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
for literal in (
    "#![forbid(unsafe_code)]",
    "DurableNativeApplicationV0",
    "NativeApplicationConfigV0",
    "RuntimeObjectDeltaRootV0",
    "RuntimeObjectDeltaPlanV0",
    "execute_authenticated_block_candidate_v0",
):
    if literal not in lib:
        issues.append(f"lib.rs missing candidate boundary literal {literal!r}")
for literal in (
    "pub fn derive_canonical_lab_genesis_hash_v0",
    "canonical_lab_genesis_matches_independent_cross_language_vector_v0",
    "6f860345cc7966ba0dcec54fd57d19b12f8c768283d35c823c5506b6b2e339ce",
):
    if literal not in canonical_lab_bootstrap:
        issues.append(f"canonical bootstrap missing fixed contract literal {literal!r}")
for literal in (
    "execute_complete_native_block_v0",
    "NativeBlockPreviewRequestV0",
    "NativeBlockPreviewV0",
    "PREVIEW_WRITE_PLAN_DOMAIN_V0",
    "plan_complete_state_update_v0",
    "scheduled_cutoff_manifest_refresh_write_v0",
    "validator_lifecycle_seed_write_v0",
    "validate_application_validator_projection_v0",
):
    if literal not in complete:
        issues.append(f"complete.rs missing full-state execution literal {literal!r}")
for literal in (
    "impl NativeApplicationV0 for DurableNativeApplicationV0",
    "const APPLICATION_SCHEMA_VERSION_V0: u64 = 3;",
    "block_id BLOB PRIMARY KEY",
    "native_durable_execution_p_v0",
    "native_h1_state_sync_trusted_base_v0",
    "install_h1_state_sync_trusted_base_v0",
    "confirm_h1_state_sync_trusted_base_exact_v0",
    "h1_state_sync_anchor_trusted_base_installs_without_local_p_and_accepts_first_durable_child",
    "h1_state_sync_trusted_base_rejects_foreign_proof_request_and_used_store",
    "h1_state_sync_trusted_base_tamper_is_rejected_on_reopen",
    "fresh_validate_p_v0",
    "validate_target_snapshot_v0",
    "validate_p_inventory_v0",
    "resolve_parent_store_v0",
    "prepared_blocks_not_descending_from_v0",
    "application_commit_id_v0",
    "durable_overlay_dag_survives_restart_and_finalized_prefix_prunes_only_forks",
    "partial_commit_third_states_are_permanently_fenced_on_reopen",
    "immutable=1",
    "ValidationReplayRequired",
    "P_STATUS_PREPARED",
    "P_STATUS_COMMITTED",
    "native-complete-durable-p-v0.json",
    "assert_complete_vector_v0",
):
    if literal not in durable:
        issues.append(f"durable.rs missing durable-P boundary literal {literal!r}")
for literal in (
    "This is not a complete frozen-v0 ordinary-block `StateRoot`",
    "fn incorrectly_promote(root: RuntimeObjectDeltaRootV0) -> StateRoot",
    "from_legacy_snapshot_v0",
    "CompleteStatePlanV0",
    "encode_authenticated_snapshot_v0",
    "decode_authenticated_snapshot_v0",
):
    if literal not in store:
        issues.append(f"store.rs missing boundary literal {literal!r}")
for literal in (
    "exact_inner_json_is_not_reencoded_as_authority",
    "excluded_legacy_authored_vector_matches_native_runtime_and_jmt_bytes",
    "VECTOR_SHA256",
):
    if literal not in tests:
        issues.append(f"tests.rs missing differential literal {literal!r}")
for literal in (
    "complete post-state",
    "independent immutable preview request",
    "BlockId-keyed overlay DAG",
    "A QC is never interpreted as an application commit",
    "atomically records the canonical `NativeExecutedBlockV0` artifact",
    "no Core permit or Valid callback",
    "whole-machine anti-rollback authority",
    "not wired into the default Node",
    "The automatic boundary gate never builds or executes the excluded historical",
    "That command intentionally compiles archived Tendermint/ABCI dependencies.",
    "automatic workflows and the main truth gate",
):
    if literal not in readme:
        issues.append(f"README missing trust-boundary literal {literal!r}")

raw_vector = vector_path.read_bytes()
expected_hash = vector_hash_path.read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
    issues.append("vector .sha256 must contain one raw lowercase SHA-256 digest")
if hashlib.sha256(raw_vector).hexdigest() != expected_hash:
    issues.append("checked vector raw-file SHA-256 mismatch")
vector = json.loads(raw_vector)
if vector.get("schema") != "trnm.native-execution-v0.legacy-differential.v1":
    issues.append("checked vector schema changed")
if vector.get("authority") != "excluded-trnm-consensus-app-test":
    issues.append("checked vector authority changed")
expected = vector.get("expected", {})
for field in (
    "payload_root_hex", "receipts_root_hex", "evidence_root_hex",
    "runtime_object_delta_root_hex", "execution_receipts_cev0_hex", "runtime_writes",
):
    if field not in expected:
        issues.append(f"checked vector missing expected field {field}")

raw_complete_vector = complete_vector_path.read_bytes()
expected_complete_hash = complete_vector_hash_path.read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9a-f]{64}", expected_complete_hash):
    issues.append("complete vector .sha256 must contain one raw lowercase SHA-256 digest")
if hashlib.sha256(raw_complete_vector).hexdigest() != expected_complete_hash:
    issues.append("complete vector raw-file SHA-256 mismatch")
complete_vector = json.loads(raw_complete_vector)
if complete_vector.get("schema") != "trnm.native-execution-v0.complete-durable-p.v1":
    issues.append("complete durable-P vector schema changed")
if complete_vector.get("classification") != "candidate-non-production":
    issues.append("complete durable-P vector classification changed")
complete_expected = complete_vector.get("expected", {})
for field in (
    "payload_root_hex", "post_state_root_hex", "receipts_root_hex",
    "evidence_root_hex", "durable_sequence_after_p",
    "durable_sequence_after_commit", "prepared_recovery_disposition",
    "committed_recovery_disposition",
):
    if field not in complete_expected:
        issues.append(f"complete durable-P vector missing expected field {field}")
if complete_vector.get("authority_boundary") != {
    "core_application_seal": False,
    "safety_authority": False,
    "whole_node_checkpoint_cas": False,
    "request_signature": False,
    "signing_or_broadcast": False,
    "production_candidate": False,
}:
    issues.append("complete durable-P vector authority boundary changed")

archive_package = archive_manifest.get("package", {})
for key, expected_value in (
    ("edition", "2021"), ("license", "MIT"),
    ("authors", ["Trillionnium Contributors"]),
):
    if archive_package.get(key) != expected_value:
        issues.append(f"excluded archive package.{key} is not standalone")
if archive_manifest.get("workspace") != {"resolver": "2"}:
    issues.append("excluded legacy authoring package is not a standalone workspace")
archive_source = archive_source_path.read_text(encoding="utf-8")
for literal in (
    "author_native_execution_differential_vector_v0",
    "emit_native_execution_differential_vector_v0",
    "checked_native_execution_differential_vector_is_legacy_reproducible_v0",
):
    if literal not in archive_source:
        issues.append(f"excluded legacy source missing author/check literal {literal!r}")

if issues:
    print("; ".join(issues))
    raise SystemExit(1)
PY

graph="$(cargo tree --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 -e normal,build)"
if grep -Eiq 'comet|tendermint|abci|trnm-consensus-app|trnm-node' <<<"$graph"; then
  fail "active native execution dependency graph regained an archive dependency"
fi

cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --all-targets
cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --doc
cargo clippy --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --all-targets -- -D warnings

printf '%s\n' \
  'TRNM native execution v0 boundary gate passed (full frozen-v0 deterministic state root plus durable P/fresh readback; no archive build, Core/Safety authority, RequestSignature, signing, or production activation).'
