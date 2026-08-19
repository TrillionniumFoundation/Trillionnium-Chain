#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-verify-challenge-v1"
SCHEMA="docs/protocol/poco-ai-native-v1/schema/cev1-verify-challenge-kernel-v1.json"
VECTORS="docs/protocol/poco-ai-native-v1/vectors/cev1-verify-challenge-kernel-v1.json"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
SPEC_MANIFEST="docs/protocol/poco-ai-native-v1/spec-manifest.toml"
WORKFLOW=".github/workflows/trnm-poco-bft-v0.yml"
DESIGN_TRUTH="scripts/ci/check_poco_ai_native_v1_design_truth.sh"
MAIN_TRUTH="scripts/ci/check_poco_bft_v0_ci_truth.sh"

CANDIDATE_INVENTORY=(
  "trillionnium/Cargo.toml"
  "trillionnium/Cargo.lock"
  "$CRATE/Cargo.toml"
  "$CRATE/README.md"
  "$CRATE/src/codec.rs"
  "$CRATE/src/error.rs"
  "$CRATE/src/lib.rs"
  "$CRATE/src/store.rs"
  "$CRATE/src/tests.rs"
  "$CRATE/src/types.rs"
  "$SCHEMA"
  "$VECTORS"
  "$STATUS"
  "$SPEC_MANIFEST"
  "RELEASE_READINESS.md"
  "docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md"
  "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
  "docs/protocol/poco-ai-native-v1/schema/README.md"
  "docs/protocol/poco-ai-native-v1/vectors/README.md"
  "$WORKFLOW"
  "$DESIGN_TRUTH"
  "$MAIN_TRUTH"
  "scripts/ci/check_trnm_poco_verify_challenge_v1_boundary.sh"
)

fail() { printf 'PoCO Verify/Challenge v1 candidate boundary gate failed: %s\n' "$*" >&2; exit 1; }

check_candidate_index() {
  local relative
  for relative in "${CANDIDATE_INVENTORY[@]}"; do
    git cat-file -e ":$relative" >/dev/null 2>&1 || fail "candidate index omits $relative"
    git diff --quiet -- "$relative" || fail "candidate index differs from worktree for $relative"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  check_candidate_index
  printf 'PoCO Verify/Challenge v1 candidate index binding: PASS\n'
  exit 0
fi

for path in "${CANDIDATE_INVENTORY[@]}"; do test -s "$path" || fail "missing/nonempty $path"; done

python3 - "trillionnium/Cargo.toml" "$CRATE/Cargo.toml" "$CRATE" "$SCHEMA" "$VECTORS" <<'PY'
import json, pathlib, re, sys, tomllib
workspace_path, manifest_path, crate_root, schema_path, vectors_path = map(pathlib.Path, sys.argv[1:])
workspace=tomllib.loads(workspace_path.read_text()); manifest=tomllib.loads(manifest_path.read_text())
schema=json.loads(schema_path.read_text()); vectors=json.loads(vectors_path.read_text())
assert "crates/trnm-poco-verify-challenge-v1" in workspace["workspace"]["members"]
assert manifest["package"]["name"] == "trnm-poco-verify-challenge-v1"
assert manifest["package"]["publish"] is False
assert manifest["features"] == {"default": []}
assert set(manifest["dependencies"]) == {"borsh","ed25519-dalek","rusqlite","sha2","trnm-poco-agent-market-v1"}
assert manifest["package"]["metadata"]["trnm"]["classification"] == "candidate-non-normative"
assert manifest["package"]["metadata"]["trnm"]["verification_class"] == "stake-quorum-only"
for key in ["bootstrap_unique_trust_keys","committed_profile_hash_recomputed","order_finalized_execution_context_cas","execution_receipt_kernel","atomic_evaluation_pair","challenge_evidence_response_adjudication_kernel","verifier_identity_weighted_quorum","exact_claim_statement_evidence_sequence_binding","required_da_policy_hash_bound","checked_transition_arithmetic","immutable_read_only_existing_file_preflight","durable_state_and_journal_tail_roots","durable_finalized_order_block_journal"]:
    assert manifest["package"]["metadata"]["trnm"][key] is True
assert manifest["package"]["metadata"]["trnm"]["required_registered_verifier_count"] == 4
assert manifest["package"]["metadata"]["trnm"]["maximum_evidence_entries"] == 64
for key in ["fresh_genesis_trust_bundle_is_consensus_object","order_finalized_execution_context_is_consensus_object","order_proof_authority_complete"]:
    assert manifest["package"]["metadata"]["trnm"][key] is False
for key in ["settlement_integration","artifact_da_verification","agent_transaction_wire_complete","whole_store_rollback_authority","node_integration","g2_global_complete","protocol_implementation_complete","normative_freeze","production_candidate","activation"]:
    assert manifest["package"]["metadata"]["trnm"][key] is False
assert {p.name for p in (crate_root/"src").glob("*.rs")} == {"codec.rs","error.rs","lib.rs","store.rs","tests.rs","types.rs"}
for path in [manifest_path, *(crate_root/"src").glob("*.rs")]:
    assert not re.search(r"tendermint|\\babci\\b|comet|trnm-consensus-app", path.read_text(), re.I), path
assert schema["status"] == "candidate-non-normative"
assert schema["verification"]["class"] == "StakeQuorum"
assert schema["verification"]["all_seven_classes_complete"] is False
assert schema["verification"]["verifier_identities_strictly_sorted_unique"] is True
assert schema["verification"]["claim_ids_are_uniqueness_authority"] is False
assert schema["verification"]["exact_shared_statement_evidence_sequence"] is True
assert schema["verification"]["required_da_policy_hash_bound"] is True
assert schema["verification"]["required_registered_verifier_count"] == 4
assert schema["trust_input"]["duplicate_key_ids_or_public_keys_rejected"] is True
assert schema["trust_input"]["verifier_set_hash_recomputed"] is True
assert schema["trust_input"]["profile_hash_recomputed"] is True
assert schema["trust_input"]["profile_hash_domain"] == "trnm.poco-ai.stake-quorum-profile.candidate.v1"
assert schema["order_finalized_execution_context"]["durable_expected_tip_cas"] is True
assert schema["order_finalized_execution_context"]["node_order_proof_authority_complete"] is False
assert schema["result_lifecycle"]["atomic_evaluation_pair"] is True
assert schema["result_lifecycle"]["challenge_open_binds_persisted_evaluation_statement"] is True
assert schema["challenge_lifecycle"]["bond_transition_atomic"] is True
assert schema["challenge_lifecycle"]["maximum_evidence_entries"] == 64
assert schema["storage"]["journal_schema_version"] == 3
assert schema["storage"]["tables"] == 3
assert schema["storage"]["automatic_migration"] is False
assert schema["storage"]["immutable_read_only_existing_file_preflight"] is True
assert schema["storage"]["third_state_permanent_fence"] is True
assert schema["storage"]["durable_state_root_checked_every_open_read_write"] is True
assert schema["storage"]["durable_journal_root_checked_every_open_read_write"] is True
assert schema["storage"]["operation_tail_binds_state"] is True
assert schema["storage"]["durable_finalized_order_block_journal"] is True
assert schema["storage"]["direct_successor_finalized_block_markers"] is True
assert schema["storage"]["empty_finalized_blocks_advance"] is True
assert schema["storage"]["same_block_multiple_operations"] is True
assert schema["storage"]["finalized_block_journal_binds_order_tip"] is True
assert schema["storage"]["finalized_block_root_checked_every_open_read_write"] is True
assert schema["storage"]["whole_store_rollback_authority"] is False
assert all(value is False for value in schema["global_truth"].values())
assert vectors["counts"]["positive"] == len(vectors["positive_cases"]) == 16
assert vectors["counts"]["negative"] == len(vectors["negative_cases"]) == 30
assert vectors["counts"]["crash_reopen"] == len(vectors["crash_reopen_cases"]) == 6
assert len(set(vectors["negative_cases"])) == 30
assert all(value is False for value in vectors["global_truth"].values())
PY

if [[ "${1:-}" == "--static-only" ]]; then
  echo "PASS: PoCO Verify/Challenge v1 candidate static boundary"
  exit 0
fi

candidate_tmp="$(mktemp -d)"; trap 'rm -rf -- "$candidate_tmp"' EXIT
candidate_index="$candidate_tmp/candidate.index"
GIT_INDEX_FILE="$candidate_index" git read-tree HEAD
GIT_INDEX_FILE="$candidate_index" git add -- "${CANDIDATE_INVENTORY[@]}"
GIT_INDEX_FILE="$candidate_index" "$0" --candidate-index-only >/dev/null
for omitted in "${CANDIDATE_INVENTORY[@]}"; do
  mutant="$candidate_tmp/$(printf '%s' "$omitted" | sha256sum | cut -d' ' -f1).index"
  cp "$candidate_index" "$mutant"
  GIT_INDEX_FILE="$mutant" git rm --cached --quiet -- "$omitted"
  if GIT_INDEX_FILE="$mutant" "$0" --candidate-index-only >/dev/null 2>&1; then fail "omission mutant survived for $omitted"; fi
done

cargo metadata --manifest-path trillionnium/Cargo.toml --no-deps --format-version 1 --offline |
  python3 -c 'import json,sys; assert any(p["name"]=="trnm-poco-verify-challenge-v1" for p in json.load(sys.stdin)["packages"])' || fail "cargo metadata omits crate"
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-verify-challenge-v1 --locked --offline
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-verify-challenge-v1 --locked --offline vector_inventory_matches_executable_candidate_assertions
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-poco-verify-challenge-v1 --all-targets --locked --offline -- -D warnings

printf 'PASS: PoCO Verify/Challenge v1 candidate boundary\n'
