#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-agent-market-v1"
SCHEMA="docs/protocol/poco-ai-native-v1/schema/cev1-agent-market-kernel-v1.json"
VECTORS="docs/protocol/poco-ai-native-v1/vectors/cev1-agent-market-kernel-v1.json"
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
  "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
  "docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md"
  "docs/protocol/poco-ai-native-v1/schema/README.md"
  "docs/protocol/poco-ai-native-v1/vectors/README.md"
  "$WORKFLOW"
  "$DESIGN_TRUTH"
  "$MAIN_TRUTH"
  "scripts/ci/check_trnm_poco_agent_market_v1_boundary.sh"
)

fail() {
  printf 'PoCO Agent/Market v1 candidate boundary gate failed: %s\n' "$*" >&2
  exit 1
}

check_candidate_index() {
  local relative
  for relative in "${CANDIDATE_INVENTORY[@]}"; do
    git cat-file -e ":$relative" >/dev/null 2>&1 ||
      fail "candidate index omits $relative"
    git diff --quiet -- "$relative" ||
      fail "candidate index differs from worktree for $relative"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  check_candidate_index
  printf 'PoCO Agent/Market v1 candidate index binding: PASS\n'
  exit 0
fi

for path in "${CANDIDATE_INVENTORY[@]}"; do
  test -s "$path" || fail "missing/nonempty required Agent/Market candidate file: $path"
done

python3 - "trillionnium/Cargo.toml" "$CRATE/Cargo.toml" "$CRATE" "$SCHEMA" "$VECTORS" <<'PY'
import json, pathlib, re, sys, tomllib

workspace_path, manifest_path, crate_root, schema_path, vectors_path = map(pathlib.Path, sys.argv[1:])
workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
schema = json.loads(schema_path.read_text(encoding="utf-8"))
vectors = json.loads(vectors_path.read_text(encoding="utf-8"))

assert "crates/trnm-poco-agent-market-v1" in workspace["workspace"]["members"]
assert manifest["package"]["name"] == "trnm-poco-agent-market-v1"
assert manifest["package"]["publish"] is False
assert manifest["features"] == {"default": []}
assert set(manifest["dependencies"]) == {"borsh", "ed25519-dalek", "rusqlite", "sha2"}
assert set(manifest["dev-dependencies"]) == {"hex", "serde_json", "tempfile"}
assert manifest["package"]["metadata"]["trnm"] == {
    "lane": "poco-ai-native-v1-agent-market-candidate",
    "protocol": "poco-ai-native-v1",
    "classification": "candidate-non-normative",
    "fresh_genesis_trust_bundle_is_consensus_object": False,
    "bootstrap_identity_key_derivation_authority_complete": False,
    "order_finalized_execution_context_is_consensus_object": False,
    "order_finalized_execution_context_cas": True,
    "order_proof_authority_complete": False,
    "agent_transaction_wire_complete": False,
    "identity_and_key_lifecycle_complete": False,
    "capability_session_nonce_kernel": True,
    "task_funded_escrow_bid_lease_kernel": True,
    "sqlite_atomic_replay_kernel": True,
    "exact_scope_enforcement": True,
    "committed_resource_scope_verifier": False,
    "durable_state_and_journal_tail_roots": True,
    "durable_finalized_order_block_journal": True,
    "whole_store_rollback_authority": False,
    "node_integration": False,
    "g2_global_complete": False,
    "protocol_implementation_complete": False,
    "normative_freeze": False,
    "production_candidate": False,
    "activation": False,
}
assert {path.name for path in (crate_root / "src").glob("*.rs")} == {
    "codec.rs", "error.rs", "lib.rs", "store.rs", "tests.rs", "types.rs"
}
for path in [manifest_path, *(crate_root / "src").glob("*.rs")]:
    assert not re.search(r"tendermint|\\babci\\b|comet|trnm-consensus-app", path.read_text(encoding="utf-8"), re.I), path
assert schema["status"] == "candidate-non-normative"
assert schema["storage"]["journal_schema_version"] == 3
assert schema["storage"]["tables"] == 4
assert schema["trust_input"]["consensus_object"] is False
assert schema["authority"]["signature_scheme"] == "strict-ed25519"
assert schema["authority"]["session_lane_zero_forbidden"] is True
assert schema["storage"]["automatic_migration"] is False
assert schema["storage"]["sidecars_fail_closed"] is True
assert schema["storage"]["exact_replay"] is True
assert schema["storage"]["third_state_permanent_fence"] is True
assert schema["storage"]["durable_state_root_checked_every_open_read_write"] is True
assert schema["storage"]["durable_journal_root_checked_every_open_read_write"] is True
assert schema["storage"]["durable_finalized_order_block_journal"] is True
assert schema["storage"]["direct_successor_finalized_block_markers"] is True
assert schema["storage"]["empty_finalized_blocks_advance"] is True
assert schema["storage"]["same_block_multiple_operations"] is True
assert schema["storage"]["finalized_block_root_checked_every_open_read_write"] is True
assert schema["storage"]["whole_store_rollback_authority"] is False
assert schema["scope_enforcement"]["committed_set_without_verifier_fails_closed"] is True
assert schema["scope_enforcement"]["provider_accept_resolves_lease_to_task"] is True
assert schema["order_finalized_execution_context"]["durable_expected_tip_cas"] is True
assert schema["order_finalized_execution_context"]["node_order_proof_authority_complete"] is False
assert schema["global_truth"]["g2_global_complete"] is False
assert schema["global_truth"]["production_candidate"] is False
assert schema["global_truth"]["activation"] is False
assert vectors["counts"]["positive"] == len(vectors["positive_cases"]) == 13
assert vectors["counts"]["negative"] == len(vectors["negative_cases"]) == 58
assert vectors["counts"]["crash_reopen"] == len(vectors["crash_reopen_cases"]) == 6
assert len(set(vectors["negative_cases"])) == 58
assert vectors["global_truth"]["g2_global_complete"] is False
PY

rg -q 'g2_global_complete = false' "$CRATE/Cargo.toml"
rg -q 'protocol_implementation_complete = false' "$CRATE/Cargo.toml"
rg -q 'production_candidate = false' "$CRATE/Cargo.toml"
rg -q 'activation = false' "$CRATE/Cargo.toml"
rg -q 'fully funded Escrow' "$CRATE/README.md"
rg -q '"third_state_permanent_fence": true' "$SCHEMA"
rg -q '"committed_set_without_verifier_fails_closed": true' "$SCHEMA"
rg -q '"durable_expected_tip_cas": true' "$SCHEMA"
rg -q 'durable_state_and_journal_tail_roots = true' "$CRATE/Cargo.toml"
rg -q 'durable_finalized_order_block_journal = true' "$CRATE/Cargo.toml"
rg -q '"whole_store_rollback_authority": false' "$SCHEMA"

if [[ "${1:-}" == "--static-only" ]]; then
  echo "PASS: PoCO Agent/Market v1 candidate static boundary"
  exit 0
fi

# Prove every implementation/truth byte is required in the proposed commit.
# Mutation is confined to temporary indexes; the real index is never changed.
candidate_tmp="$(mktemp -d)"
trap 'rm -rf -- "$candidate_tmp"' EXIT
candidate_index="$candidate_tmp/candidate.index"
GIT_INDEX_FILE="$candidate_index" git read-tree HEAD
GIT_INDEX_FILE="$candidate_index" git add -- "${CANDIDATE_INVENTORY[@]}"
GIT_INDEX_FILE="$candidate_index" "$0" --candidate-index-only >/dev/null
for omitted in "${CANDIDATE_INVENTORY[@]}"; do
  mutant_index="$candidate_tmp/$(printf '%s' "$omitted" | sha256sum | cut -d' ' -f1).index"
  cp -- "$candidate_index" "$mutant_index"
  GIT_INDEX_FILE="$mutant_index" git rm --cached --quiet -- "$omitted"
  if GIT_INDEX_FILE="$mutant_index" "$0" --candidate-index-only >/dev/null 2>&1; then
    fail "candidate omission mutant survived for $omitted"
  fi
done

cargo metadata --manifest-path trillionnium/Cargo.toml --no-deps --format-version 1 --offline |
  python3 -c 'import json,sys; data=json.load(sys.stdin); assert any(p["name"]=="trnm-poco-agent-market-v1" for p in data["packages"])' ||
  fail "cargo metadata omits trnm-poco-agent-market-v1"

cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-agent-market-v1 --locked --offline
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-poco-agent-market-v1 --locked --offline vector_inventory_matches_executable_negative_assertions
cargo clippy --manifest-path trillionnium/Cargo.toml -p trnm-poco-agent-market-v1 --all-targets --locked --offline -- -D warnings

echo "PASS: PoCO Agent/Market v1 candidate boundary"
