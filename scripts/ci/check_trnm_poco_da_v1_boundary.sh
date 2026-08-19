#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
WORKSPACE="$ROOT/trillionnium/Cargo.toml"
LOCKFILE="$ROOT/trillionnium/Cargo.lock"
CRATE="$ROOT/trillionnium/crates/trnm-poco-da-v1"
MANIFEST="$CRATE/Cargo.toml"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-transaction-batch-da-kernel-v1.json"
VECTORS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-transaction-batch-da-kernel-v1.json"
STATUS="$ROOT/docs/protocol/poco-ai-native-v1/status.toml"
PLAN="$ROOT/docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md"
GAPS="$ROOT/docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
SPEC_MANIFEST="$ROOT/docs/protocol/poco-ai-native-v1/spec-manifest.toml"
WORKFLOW="$ROOT/.github/workflows/trnm-poco-bft-v0.yml"
DESIGN_TRUTH="$ROOT/scripts/ci/check_poco_ai_native_v1_design_truth.sh"
MAIN_TRUTH="$ROOT/scripts/ci/check_poco_bft_v0_ci_truth.sh"

CANDIDATE_INVENTORY=(
  "trillionnium/Cargo.toml"
  "trillionnium/Cargo.lock"
  "trillionnium/crates/trnm-poco-da-v1/Cargo.toml"
  "trillionnium/crates/trnm-poco-da-v1/README.md"
  "trillionnium/crates/trnm-poco-da-v1/src/codec.rs"
  "trillionnium/crates/trnm-poco-da-v1/src/error.rs"
  "trillionnium/crates/trnm-poco-da-v1/src/lib.rs"
  "trillionnium/crates/trnm-poco-da-v1/src/retrieval.rs"
  "trillionnium/crates/trnm-poco-da-v1/src/store.rs"
  "trillionnium/crates/trnm-poco-da-v1/src/tests.rs"
  "trillionnium/crates/trnm-poco-da-v1/src/types.rs"
  "docs/protocol/poco-ai-native-v1/schema/cev1-transaction-batch-da-kernel-v1.json"
  "docs/protocol/poco-ai-native-v1/vectors/cev1-transaction-batch-da-kernel-v1.json"
  "docs/protocol/poco-ai-native-v1/status.toml"
  "docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md"
  "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
  "docs/protocol/poco-ai-native-v1/spec-manifest.toml"
  ".github/workflows/trnm-poco-bft-v0.yml"
  "scripts/ci/check_poco_ai_native_v1_design_truth.sh"
  "scripts/ci/check_poco_bft_v0_ci_truth.sh"
  "scripts/ci/check_trnm_poco_da_v1_boundary.sh"
)

fail() {
  printf 'PoCO DA v1 candidate boundary gate failed: %s\n' "$*" >&2
  exit 1
}

check_candidate_index() {
  local relative
  for relative in "${CANDIDATE_INVENTORY[@]}"; do
    (cd "$ROOT" && git cat-file -e ":$relative") >/dev/null 2>&1 ||
      fail "candidate index omits $relative"
    (cd "$ROOT" && git diff --quiet -- "$relative") ||
      fail "candidate index differs from worktree for $relative"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  check_candidate_index
  printf 'PoCO DA v1 candidate index binding: PASS\n'
  exit 0
fi

for required in "$WORKSPACE" "$LOCKFILE" "$MANIFEST" "$CRATE/README.md" \
  "$CRATE/src/codec.rs" "$CRATE/src/error.rs" "$CRATE/src/lib.rs" \
  "$CRATE/src/retrieval.rs" "$CRATE/src/store.rs" "$CRATE/src/tests.rs" \
  "$CRATE/src/types.rs" \
  "$SCHEMA" "$VECTORS" "$STATUS" "$PLAN" "$GAPS" "$SPEC_MANIFEST" "$WORKFLOW" \
  "$DESIGN_TRUTH" "$MAIN_TRUTH"; do
  [[ -f "$required" ]] || fail "missing ${required#$ROOT/}"
done

python3 - "$WORKSPACE" "$MANIFEST" "$CRATE" "$SCHEMA" "$VECTORS" \
  "$CRATE/README.md" "$STATUS" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

workspace_path, manifest_path, crate_root, schema_path, vectors_path, readme_path, status_path = map(pathlib.Path, sys.argv[1:])
issues: list[str] = []

with workspace_path.open("rb") as source:
    workspace = tomllib.load(source)
with manifest_path.open("rb") as source:
    manifest = tomllib.load(source)
with schema_path.open(encoding="utf-8") as source:
    schema = json.load(source)
with vectors_path.open(encoding="utf-8") as source:
    vectors = json.load(source)
with status_path.open("rb") as source:
    status = tomllib.load(source)

if "crates/trnm-poco-da-v1" not in workspace.get("workspace", {}).get("members", []):
    issues.append("active workspace omits trnm-poco-da-v1")

expected_package = {
    "name": "trnm-poco-da-v1",
    "version": "0.1.0",
    "edition": "2021",
    "license": "MIT",
    "authors": ["Trillionnium Contributors"],
    "publish": False,
}
package = manifest.get("package", {})
for key, expected in expected_package.items():
    if type(package.get(key)) is not type(expected) or package.get(key) != expected:
        issues.append(f"package.{key}={package.get(key)!r}, expected {expected!r}")

expected_metadata = {
    "lane": "poco-ai-native-v1-transaction-batch-da-candidate",
    "protocol": "poco-ai-native-v1",
    "classification": "candidate-non-normative",
    "namespace": "transaction-batch-only",
    "artifact_evidence_namespace": False,
    "cev1_global_schema_complete": False,
    "transaction_envelope_parser_complete": False,
    "durable_before_attest_local_kernel": True,
    "attestation_high_watermark": True,
    "anti_whole_store_rollback_authority": False,
    "immutable_durable_manifest_checksum": True,
    "signed_full_range_retrieval_proof_candidate": True,
    "proof_driven_exact_repair_candidate": True,
    "canonical_multilevel_chunk_paths_checked": True,
    "certificate_author_policy_key_binding": True,
    "repair_window_enforced": True,
    "authoritative_repair_height_source": False,
    "generic_chunk_range_retrieval": False,
    "requester_registry_integration": False,
    "durable_responder_signer_journal": False,
    "withholding_adjudication": False,
    "gc_permit_public_constructor": False,
    "production_gc_authority": False,
    "external_byte_deletion_reachable": False,
    "network_service": False,
    "whole_node_checkpoint_integration": False,
    "node_integration": False,
    "protocol_implementation_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
metadata = package.get("metadata", {}).get("trnm", {})
if metadata != expected_metadata:
    issues.append(f"package.metadata.trnm={metadata!r}, expected {expected_metadata!r}")

if manifest.get("features") != {"default": []}:
    issues.append("default feature set must be empty")
if set(manifest.get("dependencies", {})) != {"borsh", "ed25519-dalek", "rusqlite", "sha2"}:
    issues.append("normal dependencies must be the exact zero-Comet candidate set")
if set(manifest.get("dev-dependencies", {})) != {"hex", "serde", "serde_json", "tempfile"}:
    issues.append("unexpected dev-dependency inventory")

retrieval_evidence = status.get("evidence_tranches", {}).get("transaction_batch_da_kernel", {})
for key, expected in {
    "signed_full_range_retrieval_proof_candidate": True,
    "proof_driven_exact_repair_candidate": True,
    "signed_retrieval_positive_cases_checked": 1,
    "signed_retrieval_negative_controls_checked": 14,
    "signed_retrieval_compile_fail_cases_checked": 4,
    "canonical_certified_chunk_inclusion_paths": True,
    "canonical_multilevel_chunk_paths_checked": True,
    "certificate_author_policy_key_binding": True,
    "repair_window_enforced": True,
    "authoritative_repair_height_source": False,
    "target_scope_store_config_certificate_binding": True,
    "generic_chunk_range_retrieval": False,
    "requester_registry_integration": False,
    "durable_responder_signer_journal": False,
    "withholding_adjudication": False,
    "network_service": False,
    "node_integration": False,
    "data_availability_plane_implemented": False,
    "production_candidate": False,
    "activation": False,
}.items():
    if retrieval_evidence.get(key) != expected:
        issues.append(f"status transaction-batch DA {key} must be {expected!r}")

expected_sources = {
    "codec.rs", "error.rs", "lib.rs", "retrieval.rs", "store.rs", "tests.rs", "types.rs"
}
actual_sources = {path.name for path in (crate_root / "src").glob("*.rs")}
if actual_sources != expected_sources:
    issues.append(f"source inventory={sorted(actual_sources)!r}, expected {sorted(expected_sources)!r}")

forbidden = re.compile(r"tendermint|\babci\b|comet|trnm-consensus-app", re.IGNORECASE)
for path in [manifest_path, *sorted((crate_root / "src").glob("*.rs"))]:
    match = forbidden.search(path.read_text(encoding="utf-8"))
    if match:
        issues.append(f"forbidden legacy token {match.group(0)!r} in {path.name}")

required_literals = {
    "lib.rs": [
        "#![forbid(unsafe_code)]",
        "Candidate-only local transaction-batch DA kernel",
    ],
    "types.rs": [
        "TRANSACTION_BATCH_NAMESPACE_V1",
        "ARTIFACT_EVIDENCE_NAMESPACE_V1",
        "floor(2W/3)+1",
        "AttestorEquivocationEvidenceV1",
        "strict Ed25519",
    ],
    "store.rs": [
        "BatchAvailabilityStateV1",
        "durable attestation intent",
        "attestation_high_watermark",
        "durable_manifest_checksum",
        "FinalizedGcPermitV1",
        "fresh readback",
        "max_queue_batches",
        "max_author_bytes",
        "repair_batch",
        "extend_retention",
        "release_retention",
        "garbage_collect",
        "da_gc_tombstones_v1",
        "automatic migration is forbidden",
        "unresolved SQLite sidecar is fail-closed",
        "prepare_full_range_retrieval_response_v1",
        "verify_full_range_retrieval_proof_v1",
        "repair_from_verified_retrieval_v1",
        "future-dated or stale at repair height",
    ],
    "retrieval.rs": [
        "Signed full-range retrieval proof and exact-repair candidate",
        "canonical inclusion path",
        "future-dated or stale",
        "requester registry",
        "policy.repair_window_blocks()",
        "author key differs from committed policy",
        "verified_at_height",
    ],
    "tests.rs": [
        "applied but ack-lost replay",
        "durable prepare replay",
        "bounded queue must reject third",
        "objective signed conflict evidence",
        "GC with durable tombstone",
        "tamper on reopen",
        "durable high-watermark forbids sequence reuse",
        "attestation replay after repair",
        "cross-store GC permit",
        "signed_full_range_retrieval_proof_repairs_exact_certified_bytes_and_reopens",
        "cross-store response intent",
        "certificate-spliced repair carrier",
        "non-canonical Merkle path",
        "repair window is narrower than retrieval window",
        "signed_full_range_retrieval_rejects_certificate_author_key_outside_policy",
    ],
}
for name, literals in required_literals.items():
    text = (crate_root / "src" / name).read_text(encoding="utf-8")
    for literal in literals:
        if literal not in text:
            issues.append(f"{name} lacks boundary literal {literal!r}")

if (crate_root / "src" / "lib.rs").read_text(encoding="utf-8").count("```compile_fail") != 8:
    issues.append("DA crate must retain exactly 8 external compile-fail boundaries")

if schema.get("classification") != "candidate-non-normative":
    issues.append("schema classification must remain candidate-non-normative")
if schema.get("namespace") != {
    "name": "TransactionBatch",
    "tag": 0,
    "artifact_evidence_supported": False,
}:
    issues.append("schema namespace boundary mismatch")
if schema.get("encoding", {}).get("global_cev1_wire_schema_complete") is not False:
    issues.append("schema must not claim global wire completion")
if schema.get("sqlite", {}).get("fresh_connection_readback") is not True:
    issues.append("schema must require fresh connection readback")
if schema.get("sqlite", {}).get("automatic_migration") is not False:
    issues.append("schema must forbid automatic migration")
if schema.get("sqlite", {}).get("journal_schema") != 2:
    issues.append("SQLite candidate journal schema must be exactly 2")
if schema.get("sqlite", {}).get("checksummed_attestation_high_watermark") is not True:
    issues.append("schema must bind the persistent attestation high-watermark")
if schema.get("sqlite", {}).get("anti_whole_store_rollback_authority") is not False:
    issues.append("schema must keep whole-store rollback authority false")
if schema.get("sqlite", {}).get("rowid_sequence_authority") is not False:
    issues.append("schema must reject rowid as attestation sequence authority")
if schema.get("sqlite", {}).get("immutable_durable_manifest_checksum") is not True:
    issues.append("schema must bind the immutable durable manifest")
for key, expected in {
    "gc_permit_public_constructor": False,
    "production_gc_authority": False,
    "external_byte_deletion_reachable": False,
}.items():
    if schema.get("evidence", {}).get(key) is not expected:
        issues.append(f"schema evidence.{key} must remain {expected!r}")
readme = readme_path.read_text(encoding="utf-8")
for literal in [
    "Journal schema v2",
    "high-watermark",
    "immutable durable-manifest checksum",
    "no constructor for `FinalizedGcPermitV1`",
    "downstream/production code cannot reach byte deletion",
    "signed **full-range**",
    "out-of-band trust pin",
]:
    if literal not in readme:
        issues.append(f"README lacks boundary literal {literal!r}")
if vectors.get("classification") != "candidate-non-normative":
    issues.append("vector classification mismatch")
if len(vectors.get("positive_cases", [])) != 12:
    issues.append("positive vector inventory must contain exactly 12 cases")
if len(vectors.get("negative_cases", [])) != 20:
    issues.append("negative vector inventory must contain exactly 20 cases")
if len(vectors.get("crash_and_reopen_cases", [])) != 7:
    issues.append("crash/reopen inventory must contain exactly 7 cases")
for key, value in vectors.get("global_claims", {}).items():
    if value is not False:
        issues.append(f"global claim {key} must remain false")

if issues:
    for issue in issues:
        print(f" - {issue}", file=sys.stderr)
    raise SystemExit(1)
PY

# Prove that every implementation/truth byte is required in the proposed
# commit. The mutation only alters a temporary index and never the real index.
candidate_tmp="$(mktemp -d)"
trap 'rm -rf -- "$candidate_tmp"' EXIT
candidate_index="$candidate_tmp/candidate.index"
(cd "$ROOT" && GIT_INDEX_FILE="$candidate_index" git read-tree HEAD)
(cd "$ROOT" && GIT_INDEX_FILE="$candidate_index" git add -- "${CANDIDATE_INVENTORY[@]}")
GIT_INDEX_FILE="$candidate_index" "$0" --candidate-index-only >/dev/null
for omitted in "${CANDIDATE_INVENTORY[@]}"; do
  mutant_index="$candidate_tmp/$(basename "$omitted").index"
  cp -- "$candidate_index" "$mutant_index"
  (cd "$ROOT" && GIT_INDEX_FILE="$mutant_index" git rm --cached --quiet -- "$omitted")
  if GIT_INDEX_FILE="$mutant_index" "$0" --candidate-index-only >/dev/null 2>&1; then
    fail "candidate omission mutant survived for $omitted"
  fi
done

if [[ "${1:-}" == "--static-only" ]]; then
  printf 'PoCO DA v1 static candidate boundary: PASS\n'
  exit 0
fi

cargo metadata --manifest-path "$WORKSPACE" --no-deps --format-version 1 --offline |
  python3 -c 'import json,sys; data=json.load(sys.stdin); assert any(p["name"]=="trnm-poco-da-v1" for p in data["packages"])' ||
  fail "cargo metadata does not contain trnm-poco-da-v1"

cargo test --manifest-path "$WORKSPACE" -p trnm-poco-da-v1 --no-default-features --locked --offline
cargo clippy --manifest-path "$WORKSPACE" -p trnm-poco-da-v1 --all-targets --no-default-features --locked --offline -- -D warnings

printf 'PoCO DA v1 candidate boundary gate: PASS\n'
