#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE="$ROOT/trillionnium/Cargo.toml"
CRATE="$ROOT/trillionnium/crates/trnm-poco-da-v1"
MANIFEST="$CRATE/Cargo.toml"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-transaction-batch-da-kernel-v1.json"
VECTORS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-transaction-batch-da-kernel-v1.json"

fail() {
  printf 'PoCO DA v1 candidate boundary gate failed: %s\n' "$*" >&2
  exit 1
}

for required in "$WORKSPACE" "$MANIFEST" "$SCHEMA" "$VECTORS" \
  "$CRATE/src/lib.rs" "$CRATE/src/codec.rs" "$CRATE/src/error.rs" \
  "$CRATE/src/retrieval.rs" "$CRATE/src/store.rs" "$CRATE/src/tests.rs" "$CRATE/src/types.rs"; do
  [[ -f "$required" && ! -L "$required" ]] || fail "missing regular file: ${required#$ROOT/}"
done

python3 - "$WORKSPACE" "$MANIFEST" "$CRATE" "$SCHEMA" "$VECTORS" <<'PY'
from __future__ import annotations
import json
import pathlib
import sys
import tomllib

workspace_path, manifest_path, crate_root, schema_path, vectors_path = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

with workspace_path.open("rb") as source:
    workspace = tomllib.load(source)
with manifest_path.open("rb") as source:
    manifest = tomllib.load(source)
with schema_path.open(encoding="utf-8") as source:
    schema = json.load(source)
with vectors_path.open(encoding="utf-8") as source:
    vectors = json.load(source)

if workspace.get("workspace", {}).get("members", []).count("crates/trnm-poco-da-v1") != 1:
    issues.append("workspace must contain exactly one trnm-poco-da-v1 package")

package = manifest.get("package", {})
for key, expected in {
    "name": "trnm-poco-da-v1",
    "version": "0.1.0",
    "edition": "2021",
    "license": "MIT",
    "authors": ["Trillionnium Contributors"],
    "publish": False,
}.items():
    if package.get(key) != expected:
        issues.append(f"package.{key} drift")

metadata = package.get("metadata", {}).get("trnm", {})
for key, expected in {
    "protocol": "poco-ai-native-v1",
    "classification": "candidate-non-normative",
    "namespace": "transaction-batch-only",
    "artifact_evidence_namespace": False,
    "durable_before_attest_local_kernel": True,
    "attestation_high_watermark": True,
    "anti_whole_store_rollback_authority": False,
    "immutable_durable_manifest_checksum": True,
    "signed_full_range_retrieval_proof_candidate": True,
    "proof_driven_exact_repair_candidate": True,
    "repair_window_enforced": True,
    "gc_permit_public_constructor": False,
    "production_gc_authority": False,
    "external_byte_deletion_reachable": False,
    "network_service": False,
    "node_integration": False,
    "protocol_implementation_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}.items():
    if metadata.get(key) != expected:
        issues.append(f"security metadata {key}={metadata.get(key)!r}, expected {expected!r}")

features = manifest.get("features", {})
if features.get("default") != []:
    issues.append("default feature set must remain empty")

dependencies = manifest.get("dependencies", {})
required_dependencies = {"borsh", "ed25519-dalek", "rusqlite", "sha2"}
missing_dependencies = required_dependencies - set(dependencies)
if missing_dependencies:
    issues.append(f"required dependencies missing: {sorted(missing_dependencies)!r}")
unexpected_local = sorted(name for name in dependencies if name.startswith("trnm-"))
if unexpected_local:
    issues.append(f"candidate DA kernel must not acquire implicit local product authority dependencies: {unexpected_local!r}")

required_sources = {"codec.rs", "error.rs", "lib.rs", "retrieval.rs", "store.rs", "tests.rs", "types.rs"}
actual_sources = {path.name for path in (crate_root / "src").glob("*.rs")}
missing_sources = required_sources - actual_sources
if missing_sources:
    issues.append(f"required source files missing: {sorted(missing_sources)!r}")

lib = (crate_root / "src" / "lib.rs").read_text(encoding="utf-8")
for literal in ("#![forbid(unsafe_code)]",):
    if literal not in lib:
        issues.append(f"lib.rs is missing required boundary marker {literal!r}")

if schema.get("classification") != "candidate-non-normative":
    issues.append("schema classification must remain candidate-non-normative")
if schema.get("namespace") != {
    "name": "TransactionBatch",
    "tag": 0,
    "artifact_evidence_supported": False,
}:
    issues.append("schema namespace boundary mismatch")
encoding = schema.get("encoding", {})
if encoding.get("global_cev1_wire_schema_complete") is not False:
    issues.append("schema must not claim global CEV1 wire completion")
sqlite = schema.get("sqlite", {})
for key, expected in {
    "fresh_connection_readback": True,
    "automatic_migration": False,
    "journal_schema": 2,
    "checksummed_attestation_high_watermark": True,
    "anti_whole_store_rollback_authority": False,
    "rowid_sequence_authority": False,
    "immutable_durable_manifest_checksum": True,
}.items():
    if sqlite.get(key) != expected:
        issues.append(f"schema sqlite.{key}={sqlite.get(key)!r}, expected {expected!r}")
for key, expected in {
    "gc_permit_public_constructor": False,
    "production_gc_authority": False,
    "external_byte_deletion_reachable": False,
}.items():
    if schema.get("evidence", {}).get(key) != expected:
        issues.append(f"schema evidence.{key}={schema.get('evidence', {}).get(key)!r}, expected {expected!r}")

if vectors.get("classification") != "candidate-non-normative":
    issues.append("vector classification mismatch")
for key, value in vectors.get("global_claims", {}).items():
    if value is not False:
        issues.append(f"global claim {key} must remain false")

if issues:
    raise SystemExit("\n".join(f"- {issue}" for issue in issues))
PY

cargo metadata --manifest-path "$WORKSPACE" --locked --offline --no-deps --format-version 1 >/dev/null \
  || fail "Cargo metadata does not resolve the locked offline DA package"

cargo test --manifest-path "$WORKSPACE" -p trnm-poco-da-v1 --no-default-features --locked --offline
cargo test --manifest-path "$WORKSPACE" -p trnm-poco-da-v1 --no-default-features --doc --locked --offline
cargo clippy --manifest-path "$WORKSPACE" -p trnm-poco-da-v1 --all-targets --no-default-features --locked --offline -- -D warnings

printf "%s\n" "trnm_poco_da_v1_boundary=passed,semantic_invariants_plus_executable_tests,no_closed_file_status_or_vector_count_inventory"
