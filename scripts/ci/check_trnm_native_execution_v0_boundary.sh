#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE_MANIFEST="$ROOT/trillionnium/Cargo.toml"
WORKSPACE_LOCK="$ROOT/trillionnium/Cargo.lock"
CRATE_ROOT="$ROOT/trillionnium/crates/trnm-native-execution-v0"
MANIFEST="$CRATE_ROOT/Cargo.toml"
README="$CRATE_ROOT/README.md"
COMPLETE_VECTOR="$CRATE_ROOT/vectors/native-complete-durable-p-v0.json"
COMPLETE_VECTOR_HASH="$COMPLETE_VECTOR.sha256"

fail() {
  printf 'TRNM native execution v0 boundary gate failed: %s\n' "$*" >&2
  exit 1
}

for required in \
  "$WORKSPACE_MANIFEST" "$WORKSPACE_LOCK" "$MANIFEST" "$README" \
  "$CRATE_ROOT/src/lib.rs" "$CRATE_ROOT/src/canonical_lab_bootstrap.rs" \
  "$CRATE_ROOT/src/complete.rs" "$CRATE_ROOT/src/durable.rs" \
  "$CRATE_ROOT/src/store.rs" "$CRATE_ROOT/src/tests.rs" \
  "$COMPLETE_VECTOR" "$COMPLETE_VECTOR_HASH"; do
  [[ -f "$required" ]] || fail "missing ${required#$ROOT/}"
done

python3 "$ROOT/scripts/ci/check_native_consensus_only.py" >/dev/null

python3 - "$WORKSPACE_MANIFEST" "$WORKSPACE_LOCK" "$MANIFEST" \
  "$CRATE_ROOT" "$COMPLETE_VECTOR" "$COMPLETE_VECTOR_HASH" <<'PY'
from __future__ import annotations
import hashlib
import json
import pathlib
import re
import sys
import tomllib

workspace_path, lock_path, manifest_path, crate_root, vector_path, vector_hash_path = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

def load_toml(path: pathlib.Path):
    with path.open("rb") as source:
        return tomllib.load(source)

workspace = load_toml(workspace_path)
lock = load_toml(lock_path)
manifest = load_toml(manifest_path)
members = workspace.get("workspace", {}).get("members", [])
if members.count("crates/trnm-native-execution-v0") != 1:
    issues.append("native execution package must be one active workspace member")
if workspace.get("workspace", {}).get("exclude") != ["fuzz"]:
    issues.append("workspace exclusions must contain only fuzz")
package = manifest.get("package", {})
for key, expected in {
    "name": "trnm-native-execution-v0",
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
    "production_authority": False,
    "native_application_v0_implementation": True,
    "full_ordinary_post_state_root": True,
    "system_writes_included": True,
    "qc_as_application_commit": False,
    "production_candidate": False,
}.items():
    if metadata.get(key) != expected:
        issues.append(f"package.metadata.trnm.{key} drift")
lock_names = {row.get("name") for row in lock.get("package", []) if isinstance(row, dict)}
for removed in (("trnm-consensus-" + "app"), ("trnm-" + "node")):
    if removed in lock_names:
        issues.append(f"removed package remains in Cargo.lock: {removed}")
expected_sources = {
    "auth_tree.rs", "canonical_lab_bootstrap.rs", "complete.rs", "durable.rs", "lib.rs",
    "poco_application.rs", "poco_nullifier.rs", "poco_semantics.rs", "poco_snapshot.rs",
    "poco_transition.rs", "store.rs", "tests.rs", "validator_lifecycle.rs",
}
actual_sources = {item.name for item in (crate_root / "src").glob("*.rs")}
if actual_sources != expected_sources:
    issues.append(f"native execution source inventory drift: {sorted(actual_sources)}")
raw = vector_path.read_bytes()
digest = vector_hash_path.read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(raw).hexdigest() != digest:
    issues.append("complete native vector digest mismatch")
vector = json.loads(raw)
if vector.get("schema") != "trnm.native-execution-v0.complete-durable-p.v1":
    issues.append("complete native vector schema drift")
if vector.get("classification") != "candidate-non-production":
    issues.append("complete native vector classification drift")
expected = vector.get("expected", {})
for field in (
    "payload_root_hex", "post_state_root_hex", "receipts_root_hex", "evidence_root_hex",
    "durable_sequence_after_p", "durable_sequence_after_commit",
    "prepared_recovery_disposition", "committed_recovery_disposition",
):
    if field not in expected:
        issues.append(f"complete native vector missing {field}")
if vector.get("authority_boundary") != {
    "core_application_seal": False,
    "safety_authority": False,
    "whole_node_checkpoint_cas": False,
    "request_signature": False,
    "signing_or_broadcast": False,
    "production_candidate": False,
}:
    issues.append("complete native vector authority boundary drift")
if issues:
    raise SystemExit("; ".join(issues))
PY

cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --all-targets
cargo test --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --doc
cargo clippy --manifest-path "$WORKSPACE_MANIFEST" --locked --offline \
  -p trnm-native-execution-v0 --all-targets -- -D warnings

printf '%s\n' 'TRNM native execution v0 boundary gate passed.'
