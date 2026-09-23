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
  printf TRNM native application SQLite boundary gate failed: %sn "$*" >&2
  exit 1
}

for required in "$WORKSPACE_MANIFEST" "$MANIFEST" "$NODE_MANIFEST" "$NODE_SOURCE" "$NODE_P_HOST" \
  "$CRATE_ROOT/src/lib.rs" "$CRATE_ROOT/src/binding.rs" "$CRATE_ROOT/src/error.rs" \
  "$CRATE_ROOT/src/store.rs" "$CRATE_ROOT/src/finalization_history.rs" "$CRATE_ROOT/src/tests.rs"; do
  [[ -f "$required" && ! -L "$required" ]] || fail "missing regular file: ${required#$ROOT/}"
done

python3 - "$WORKSPACE_MANIFEST" "$MANIFEST" "$NODE_MANIFEST" "$CRATE_ROOT" "$NODE_P_HOST" <<PY
from __future__ import annotations
import pathlib
import sys
import tomllib

workspace_path, manifest_path, node_path, crate_root, node_p_host_path = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

with workspace_path.open("rb") as source:
    workspace = tomllib.load(source)
with manifest_path.open("rb") as source:
    manifest = tomllib.load(source)
with node_path.open("rb") as source:
    node = tomllib.load(source)

if workspace.get("workspace", {}).get("members", []).count("crates/trnm-native-application-sqlite") != 1:
    issues.append("workspace must contain exactly one native application SQLite package")

package = manifest.get("package", {})
for key, expected in {
    "name": "trnm-native-application-sqlite",
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
    "protocol": "poco-bft-v0",
    "native_only": True,
    "native_application_v0_implementation": False,
    "validation_journal_schema": 5,
    "validation_journal_schema_auto_migration": False,
    "core_delivery_public_constructor": False,
    "core_delivery_authority_integration": True,
    "core_delivery_accepts_only_opaque_core_carrier": True,
    "safety_confirmation_sealed_authority": True,
    "safety_confirmation_authority_integration": True,
    "descriptor_anchored_namespace_identity": True,
    "closed_world_schema_validation": True,
    "trusted_return_after_post_close_revalidation": True,
    "fresh_connection_schema_revalidation": True,
    "wal_shm_identity_pinning": True,
    "anti_whole_machine_rollback_authority": False,
    "production_candidate": False,
}.items():
    if metadata.get(key) != expected:
        issues.append(f"security metadata {key}={metadata.get(key)!r}, expected {expected!r}")

features = manifest.get("features", {})
if features.get("default") != [] or features.get("test-support") != []:
    issues.append("default and test-support features must remain empty")
if manifest.get("build-dependencies") not in (None, {}):
    issues.append("build dependencies are not part of this boundary")

dependencies = manifest.get("dependencies", {})
required_dependencies = {
    "libc", "rusqlite", "sha2", "trnm-consensus-core",
    "trnm-consensus-safety-store", "trnm-consensus-types", "trnm-native-application",
}
missing_dependencies = required_dependencies - set(dependencies)
if missing_dependencies:
    issues.append(f"required dependencies missing: {sorted(missing_dependencies)!r}")
for name in ("trnm-native-application", "trnm-consensus-core", "trnm-consensus-safety-store", "trnm-consensus-types"):
    dependency = dependencies.get(name)
    if not isinstance(dependency, dict) or dependency.get("path") != f"../{name}":
        issues.append(f"{name} must use its exact sibling path")

node_dependency = node.get("dependencies", {}).get("trnm-native-application-sqlite")
if not isinstance(node_dependency, dict) or node_dependency.get("path") != "../trnm-native-application-sqlite":
    issues.append("node must carry the exact native application SQLite dependency")
node_truth = node.get("package", {}).get("metadata", {}).get("trnm", {})
for key, expected in {
    "native_application_durable_p_host": True,
    "native_application_durable_p_host_public_api": False,
    "native_application_durable_p_host_production_constructor": False,
    "native_application_durable_p_core_callback": True,
    "native_application_core_d_private_carrier": True,
    "native_application_safety_c_authority": True,
    "native_application_k_checkpoint_facts": True,
    "native_application_k_whole_node_cas": True,
    "native_application_finality_permit_integration": False,
    "production_candidate": False,
    "production_consensus_activation": False,
}.items():
    if node_truth.get(key) != expected:
        issues.append(f"node boundary {key}={node_truth.get(key)!r}, expected {expected!r}")

required_sources = {"binding.rs", "error.rs", "lib.rs", "store.rs", "tests.rs", "finalization_history.rs"}
actual_sources = {path.name for path in (crate_root / "src").glob("*.rs")}
missing_sources = required_sources - actual_sources
if missing_sources:
    issues.append(f"required source files missing: {sorted(missing_sources)!r}")

lib = (crate_root / "src" / "lib.rs").read_text(encoding="utf-8")
for literal in (
    "#![forbid(unsafe_code)]",
    "mod binding;",
    "mod error;",
    "mod finalization_history;",
    "mod store;",
    "CoreDeliveryConfirmationV0",
    "RequestBoundSafetyConfirmationV0",
    "SqliteNativeFinalizationHistoryV0",
    "SqliteProposalValidationStoreV0",
):
    if literal not in lib:
        issues.append(f"lib.rs is missing required boundary symbol {literal!r}")

node_p_host = node_p_host_path.read_text(encoding="utf-8")
for literal in (
    "SqliteProposalValidationStoreV0",
    "CoreIssuedValidPermitV0",
    "seal_valid_and_deliver_core_d_v0",
):
    if literal not in node_p_host:
        issues.append(f"node private P host is missing required composition symbol {literal!r}")

if issues:
    raise SystemExit("\n".join(f"- {issue}" for issue in issues))
PY

cargo metadata --manifest-path "$WORKSPACE_MANIFEST" --locked --offline --no-deps --format-version 1 >/dev/null \
  || fail "Cargo metadata could not resolve the locked offline workspace"

cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-application-sqlite --all-targets
cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-application-sqlite --doc
cargo clippy --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-application-sqlite --all-targets -- -D warnings

printf "%s\n" "trnm_native_application_sqlite_boundary=passed,semantic_invariants_plus_executable_tests,no_closed_file_dependency_or_metadata_inventory"
