#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-mvcc-fee-v1"
SCHEMA="docs/protocol/poco-ai-native-v1/schema/cev1-object-mvcc-fee-kernel-v1.json"
VECTORS="docs/protocol/poco-ai-native-v1/vectors/cev1-object-mvcc-fee-kernel-v1.json"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
SPEC_MANIFEST="docs/protocol/poco-ai-native-v1/spec-manifest.toml"
WORKFLOW=".github/workflows/trnm-poco-bft-v0.yml"
DESIGN_TRUTH="scripts/ci/check_poco_ai_native_v1_design_truth.sh"
MAIN_TRUTH="scripts/ci/check_poco_bft_v0_ci_truth.sh"

CANDIDATE_INVENTORY=(
  "trillionnium/Cargo.toml" "trillionnium/Cargo.lock"
  "$CRATE/Cargo.toml" "$CRATE/README.md"
  "$CRATE/src/codec.rs" "$CRATE/src/engine.rs" "$CRATE/src/error.rs"
  "$CRATE/src/deterministic_parallel_v1.rs"
  "$CRATE/src/lib.rs" "$CRATE/src/store.rs" "$CRATE/src/tests.rs" "$CRATE/src/types.rs"
  "$SCHEMA" "$VECTORS" "$STATUS" "$SPEC_MANIFEST"
  "RELEASE_READINESS.md"
  "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
  "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
  "docs/protocol/poco-ai-native-v1/schema/README.md"
  "docs/protocol/poco-ai-native-v1/vectors/README.md"
  "$WORKFLOW" "$DESIGN_TRUTH" "$MAIN_TRUTH"
  "scripts/ci/check_trnm_poco_mvcc_fee_v1_boundary.sh"
)

fail() { printf 'PoCO object-MVCC/fee v1 candidate boundary gate failed: %s\n' "$*" >&2; exit 1; }

check_candidate_index() {
  local relative
  for relative in "${CANDIDATE_INVENTORY[@]}"; do
    git cat-file -e ":$relative" >/dev/null 2>&1 || fail "candidate index omits $relative"
    git diff --quiet -- "$relative" || fail "candidate index differs from worktree for $relative"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  check_candidate_index
  printf 'PoCO object-MVCC/fee v1 candidate index binding: PASS\n'
  exit 0
fi

for path in "${CANDIDATE_INVENTORY[@]}"; do test -s "$path" || fail "missing/nonempty $path"; done

python3 - "trillionnium/Cargo.toml" "$CRATE/Cargo.toml" "$CRATE" "$SCHEMA" "$VECTORS" <<'PY'
import json, pathlib, re, sys, tomllib
workspace_path, manifest_path, crate_root, schema_path, vectors_path = map(pathlib.Path, sys.argv[1:])
workspace=tomllib.loads(workspace_path.read_text()); manifest=tomllib.loads(manifest_path.read_text())
schema=json.loads(schema_path.read_text()); vectors=json.loads(vectors_path.read_text())
assert "crates/trnm-poco-mvcc-fee-v1" in workspace["workspace"]["members"]
assert manifest["package"]["name"] == "trnm-poco-mvcc-fee-v1"
assert manifest["package"]["publish"] is False
assert manifest["features"] == {"default": []}
assert set(manifest["dependencies"]) == {"borsh","rusqlite","sha2"}
truth=manifest["package"]["metadata"]["trnm"]
assert truth["classification"] == "candidate-non-normative"
for key in ["object_mvcc","canonical_serial_oracle","deterministic_conflict_retry","explicit_versioned_read_write_sets","complete_success_failure_receipts","multi_resource_usage","checked_fee_arithmetic","per_transaction_fee_deltas","block_end_sorted_fee_reduction","immutable_read_only_existing_file_preflight","atomic_block_state_receipts_fees","deterministic_journal_replay_audit"]: assert truth[key] is True
for key in ["global_fee_collector_per_transaction_write","whole_store_rollback_authority","authenticated_global_state_tree","agent_transaction_wire_complete","order_proof_authority_complete","node_integration","g2_global_complete","protocol_implementation_complete","normative_freeze","production_candidate","activation"]: assert truth[key] is False
assert truth["real_parallel_worker_pool"] is True
assert truth["parallel_worker_pool_scope"] == "bounded-in-process-candidate"
assert truth["worker_count_invariant_roots"] is True
assert {p.name for p in (crate_root/"src").glob("*.rs")} == {"codec.rs","deterministic_parallel_v1.rs","engine.rs","error.rs","lib.rs","store.rs","tests.rs","types.rs"}
for path in [manifest_path, *(crate_root/"src").glob("*.rs")]:
    assert not re.search(r"tendermint|\\babci\\b|comet|trnm-consensus-app", path.read_text(), re.I), path
assert schema["status"] == "candidate-non-normative"
assert schema["execution"]["canonical_serial_oracle"] is True
assert schema["execution"]["read_version_mismatch_retries_in_canonical_index_order"] is True
assert schema["execution"]["scheduler_or_worker_timing_affects_result"] is False
assert schema["execution"]["real_parallel_worker_pool"] is False
assert schema["objects"]["explicit_declared_read_set"] is True
assert schema["objects"]["explicit_declared_write_set"] is True
assert schema["objects"]["authenticated_global_state_tree"] is False
assert schema["receipts"]["statuses"] == ["Success","Reverted","OutOfResource"]
assert schema["resources_and_fees"]["classes"] == ["OrderedBytes","StateReadBytes","StateWriteBytes","DeterministicComputeUnit"]
assert schema["resources_and_fees"]["per_transaction_fee_deltas"] is True
assert schema["resources_and_fees"]["block_end_sorted_destination_reduction"] is True
assert schema["resources_and_fees"]["global_fee_collector_per_transaction_write"] is False
assert schema["storage"]["journal_schema_version"] == 1
assert schema["storage"]["automatic_migration"] is False
assert schema["storage"]["immutable_read_only_existing_file_preflight"] is True
assert schema["storage"]["third_state_permanent_fence"] is True
assert schema["storage"]["deterministic_journal_replay_audit"] is True
assert schema["storage"]["whole_store_rollback_authority"] is False
assert all(value is False for value in schema["global_truth"].values())
assert vectors["counts"]["positive"] == len(vectors["positive_cases"]) == 12
assert vectors["counts"]["negative"] == len(vectors["negative_cases"]) == 39
assert vectors["counts"]["crash_reopen"] == len(vectors["crash_reopen_cases"]) == 6
assert len(set(vectors["negative_cases"])) == 39
assert all(value is False for value in vectors["global_truth"].values())
PY

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
  python3 -c 'import json,sys; assert any(p["name"]=="trnm-poco-mvcc-fee-v1" for p in json.load(sys.stdin)["packages"])' || fail "cargo metadata omits crate"
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-mvcc-fee-v1 --locked --offline
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-mvcc-fee-v1 --locked --offline vector_inventory_matches_executable_candidate_assertions
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-poco-mvcc-fee-v1 --all-targets --locked --offline -- -D warnings

printf 'PASS: PoCO object-MVCC/fee v1 candidate boundary\n'
