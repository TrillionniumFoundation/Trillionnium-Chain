#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-consumption-settlement-v1"
SCHEMA="docs/protocol/poco-ai-native-v1/schema/cev1-consumption-settlement-kernel-v1.json"
VECTORS="docs/protocol/poco-ai-native-v1/vectors/cev1-consumption-settlement-kernel-v1.json"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
SPEC_MANIFEST="docs/protocol/poco-ai-native-v1/spec-manifest.toml"
WORKFLOW=".github/workflows/trnm-poco-bft-v0.yml"
DESIGN_TRUTH="scripts/ci/check_poco_ai_native_v1_design_truth.sh"
MAIN_TRUTH="scripts/ci/check_poco_bft_v0_ci_truth.sh"

CANDIDATE_INVENTORY=(
  "trillionnium/Cargo.toml" "trillionnium/Cargo.lock"
  "$CRATE/Cargo.toml" "$CRATE/README.md"
  "$CRATE/src/codec.rs" "$CRATE/src/engine.rs" "$CRATE/src/error.rs"
  "$CRATE/src/lib.rs" "$CRATE/src/store.rs" "$CRATE/src/tests.rs" "$CRATE/src/types.rs"
  "$SCHEMA" "$VECTORS" "$STATUS" "$SPEC_MANIFEST"
  "RELEASE_READINESS.md"
  "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
  "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
  "docs/protocol/poco-ai-native-v1/schema/README.md"
  "docs/protocol/poco-ai-native-v1/vectors/README.md"
  "$WORKFLOW" "$DESIGN_TRUTH" "$MAIN_TRUTH"
  "scripts/ci/check_trnm_poco_consumption_settlement_v1_boundary.sh"
)

fail() { printf 'PoCO consumption/settlement v1 candidate boundary gate failed: %s\n' "$*" >&2; exit 1; }

check_candidate_index() {
  local relative
  for relative in "${CANDIDATE_INVENTORY[@]}"; do
    git cat-file -e ":$relative" >/dev/null 2>&1 || fail "candidate index omits $relative"
    git diff --quiet -- "$relative" || fail "candidate index differs from worktree for $relative"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  check_candidate_index
  printf 'PoCO consumption/settlement v1 candidate index binding: PASS\n'
  exit 0
fi

for path in "${CANDIDATE_INVENTORY[@]}"; do test -s "$path" || fail "missing/nonempty $path"; done

python3 - "trillionnium/Cargo.toml" "$CRATE/Cargo.toml" "$CRATE" "$SCHEMA" "$VECTORS" "$STATUS" "$SPEC_MANIFEST" <<'PY'
import json, pathlib, re, sys, tomllib
workspace_path, manifest_path, crate_root, schema_path, vectors_path, status_path, spec_path = map(pathlib.Path, sys.argv[1:])
workspace=tomllib.loads(workspace_path.read_text()); manifest=tomllib.loads(manifest_path.read_text())
schema=json.loads(schema_path.read_text()); vectors=json.loads(vectors_path.read_text())
status=tomllib.loads(status_path.read_text()); spec=tomllib.loads(spec_path.read_text())
assert "crates/trnm-poco-consumption-settlement-v1" in workspace["workspace"]["members"]
assert manifest["package"]["name"] == "trnm-poco-consumption-settlement-v1"
assert manifest["package"]["publish"] is False
assert manifest["features"] == {"default": []}
assert set(manifest["dependencies"]) == {"borsh","ed25519-dalek","rusqlite","sha2","trnm-poco-agent-market-v1"}
truth=manifest["package"]["metadata"]["trnm"]
assert truth["classification"] == "candidate-non-normative"
assert truth["kernel_scope"] == "single-asset-single-result-single-rollup"
for key in ["order_finalized_execution_context_cas","bilateral_receipt_signatures","monotonic_consumption_receipt_chain","gap_free_atomic_rollup_assignment","chain_assigned_rollup_challenge_window","one_shot_conserved_settlement","deterministic_journal_replay_audit","immutable_read_only_existing_file_preflight","durable_state_and_journal_tail_roots","durable_finalized_order_block_journal"]: assert truth[key] is True
for key in ["fresh_genesis_trust_bundle_is_consensus_object","order_finalized_execution_context_is_consensus_object","order_proof_authority_complete","settlement_amounts_caller_selected","agent_market_authority_integration","artifact_da_authority_integration","result_challenge_authority_integration","mvcc_final_apply_integration","whole_store_rollback_authority","node_integration","g2_global_complete","protocol_implementation_complete","normative_freeze","production_candidate","activation"]: assert truth[key] is False
assert {p.name for p in (crate_root/"src").glob("*.rs")} == {"codec.rs","engine.rs","error.rs","lib.rs","store.rs","tests.rs","types.rs"}
for path in [manifest_path, *(crate_root/"src").glob("*.rs")]:
    assert not re.search(r"tendermint|\babci\b|comet|trnm-consensus-app", path.read_text(), re.I), path
assert schema["status"] == "candidate-non-normative"
assert schema["kernel_scope"] == "single-asset-single-result-single-rollup"
assert schema["receipt"]["bilateral_ed25519_signatures"] is True
assert schema["receipt"]["checked_cumulative_usage"] is True
assert schema["receipt"]["real_agent_key_state_authority"] is False
assert schema["receipt"]["real_da_certificate_authority"] is False
assert schema["rollup"]["atomic_receipt_assignment"] is True
assert schema["rollup"]["chain_assigned_challenge_close_height"] is True
assert schema["settlement"]["amounts_caller_selected"] is False
assert schema["settlement"]["checked_input_output_conservation"] is True
assert schema["settlement"]["one_shot"] is True
assert schema["settlement"]["multiple_assets_or_rollups_complete"] is False
assert schema["storage"]["journal_schema_version"] == 2
assert schema["storage"]["tables"] == 3
assert schema["storage"]["automatic_migration"] is False
assert schema["storage"]["immutable_read_only_existing_file_preflight"] is True
assert schema["storage"]["deterministic_journal_replay_audit"] is True
assert schema["storage"]["third_state_permanent_fence"] is True
assert schema["storage"]["durable_finalized_order_block_journal"] is True
assert schema["storage"]["direct_successor_finalized_block_markers"] is True
assert schema["storage"]["empty_finalized_blocks_advance"] is True
assert schema["storage"]["same_block_multiple_operations"] is True
assert schema["storage"]["finalized_block_journal_binds_order_tip"] is True
assert schema["storage"]["finalized_block_root_checked_every_open_read_write"] is True
assert schema["storage"]["whole_store_rollback_authority"] is False
assert all(value is False for value in schema["global_truth"].values())
assert len(vectors["positive_inventory"]) == 10
assert len(vectors["negative_inventory"]) == len(set(vectors["negative_inventory"])) == 56
assert len(vectors["crash_inventory"]) == 6
e=status["evidence_tranches"]["consumption_settlement_kernel"]
assert e["classification"] == "candidate-non-normative"
assert e["positive_cases_checked"] == 10 and e["negative_cases_checked"] == 56 and e["crash_and_reopen_cases_checked"] == 6
assert e["settlement_amounts_caller_selected"] is False and e["g2_global_complete"] is False and e["node_integration"] is False
required=set(spec["required_files"])
for path in [str(schema_path),str(vectors_path),"scripts/ci/check_trnm_poco_consumption_settlement_v1_boundary.sh"]: assert path in required
PY

if [[ "${1:-}" == "--static-only" ]]; then
  echo "PASS: PoCO consumption/settlement v1 candidate static boundary"
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

cargo metadata --manifest-path trillionnium/Cargo.toml --no-deps --format-version 1 --locked --offline |
  python3 -c 'import json,sys; assert any(p["name"]=="trnm-poco-consumption-settlement-v1" for p in json.load(sys.stdin)["packages"])' || fail "cargo metadata omits crate"
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-consumption-settlement-v1 --locked --offline
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-consumption-settlement-v1 --locked --offline vector_inventory_matches_candidate_assertions
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-poco-consumption-settlement-v1 --all-targets --locked --offline -- -D warnings

printf 'PASS: PoCO consumption/settlement v1 candidate boundary\n'
