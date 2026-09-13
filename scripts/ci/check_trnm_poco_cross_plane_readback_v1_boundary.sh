#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

CRATE="trillionnium/crates/trnm-poco-cross-plane-readback-v1"
SCHEMA="docs/protocol/poco-ai-native-v1/schema/cev1-cross-plane-readback-kernel-v1.json"
VECTORS="docs/protocol/poco-ai-native-v1/vectors/cev1-cross-plane-readback-kernel-v1.json"
STATUS="docs/protocol/poco-ai-native-v1/status.toml"
SPEC="docs/protocol/poco-ai-native-v1/spec-manifest.toml"
GATE="scripts/ci/check_trnm_poco_cross_plane_readback_v1_boundary.sh"

INVENTORY=(
  trillionnium/Cargo.toml trillionnium/Cargo.lock
  "$CRATE/Cargo.toml" "$CRATE/README.md"
  "$CRATE/src/codec.rs" "$CRATE/src/error.rs" "$CRATE/src/join.rs"
  "$CRATE/src/lib.rs" "$CRATE/src/tests.rs" "$CRATE/src/types.rs"
  trillionnium/crates/trnm-poco-da-v1/src/lib.rs
  trillionnium/crates/trnm-poco-da-v1/src/store.rs
  trillionnium/crates/trnm-poco-da-v1/src/tests.rs
  trillionnium/crates/trnm-poco-da-v1/src/types.rs
  trillionnium/crates/trnm-poco-agent-market-v1/src/lib.rs
  trillionnium/crates/trnm-poco-agent-market-v1/src/store.rs
  trillionnium/crates/trnm-poco-verify-challenge-v1/src/lib.rs
  trillionnium/crates/trnm-poco-verify-challenge-v1/src/store.rs
  trillionnium/crates/trnm-poco-mvcc-fee-v1/src/lib.rs
  trillionnium/crates/trnm-poco-mvcc-fee-v1/src/store.rs
  trillionnium/crates/trnm-poco-consumption-settlement-v1/src/lib.rs
  trillionnium/crates/trnm-poco-consumption-settlement-v1/src/store.rs
  "$SCHEMA" "$VECTORS" "$STATUS" "$SPEC" "$GATE"
  docs/protocol/poco-ai-native-v1/schema/README.md
  docs/protocol/poco-ai-native-v1/vectors/README.md
  docs/protocol/poco-ai-native-v1/IMPLEMENTATION_GAP_REGISTER.md
  docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
  RELEASE_READINESS.md
  scripts/ci/check_poco_ai_native_v1_design_truth.sh
  scripts/ci/check_poco_bft_v0_ci_truth.sh
  .github/workflows/trnm-poco-bft-v0.yml
)

fail() { printf 'PoCO cross-plane readback v1 boundary failed: %s\n' "$*" >&2; exit 1; }

candidate_index() {
  local path
  for path in "${INVENTORY[@]}"; do
    git cat-file -e ":$path" >/dev/null 2>&1 || fail "candidate index omits $path"
    git diff --quiet -- "$path" || fail "candidate index differs from worktree for $path"
  done
}

if [[ "${1:-}" == "--candidate-index-only" ]]; then
  candidate_index
  printf 'PoCO cross-plane readback v1 candidate index: PASS\n'
  exit 0
fi
[[ $# -eq 0 ]] || fail "unknown argument"

for path in "${INVENTORY[@]}"; do test -s "$path" || fail "missing/nonempty $path"; done

python3 - trillionnium/Cargo.toml "$CRATE/Cargo.toml" "$SCHEMA" "$VECTORS" "$STATUS" "$SPEC" <<'PY'
import json, pathlib, sys, tomllib
workspace, manifest, schema, vectors, status, spec = [pathlib.Path(v) for v in sys.argv[1:]]
w=tomllib.loads(workspace.read_text()); m=tomllib.loads(manifest.read_text())
s=json.loads(schema.read_text()); v=json.loads(vectors.read_text())
t=tomllib.loads(status.read_text()); p=tomllib.loads(spec.read_text())
assert "crates/trnm-poco-cross-plane-readback-v1" in w["workspace"]["members"]
assert m["package"]["name"] == "trnm-poco-cross-plane-readback-v1"
assert m["features"] == {"default": []}
assert set(m["dependencies"]) == {"borsh","sha2","trnm-poco-agent-market-v1","trnm-poco-consumption-settlement-v1","trnm-poco-da-v1","trnm-poco-mvcc-fee-v1","trnm-poco-verify-challenge-v1"}
truth=m["package"]["metadata"]["trnm"]
for key in ["five_plane_fresh_readback_join","double_sampled_no_intervening_change","same_da_head_and_certificate_sqlite_snapshot","explicit_typed_identifier_adapters","terminal_receipts_match_sampled_store_heads","cross_plane_readback_consistent_candidate"]: assert truth[key] is True
for key in ["order_proof_authority_complete","cross_plane_atomic_commit","cross_plane_authority_integration","whole_node_checkpoint_integration","anti_whole_store_rollback_authority","node_private_owner","node_process_integration","g2_global_complete","protocol_implementation_complete","normative_freeze","production_candidate","activation"]: assert truth[key] is False
assert s["join"]["fresh_reopen_each_store"] is True
assert s["join"]["double_sample_no_intervening_change"] is True
assert s["join"]["same_da_head_and_certificate_sqlite_snapshot"] is True
assert s["join"]["terminal_receipts_match_sampled_store_heads"] is True
assert s["join"]["order_proof_is_trust_input"] is True
assert all(value is False for key,value in s["authority"].items() if key != "cross_plane_readback_consistent_candidate")
assert all(value is False for value in s["global_truth"].values())
assert len(v["positive_inventory"]) == 3
assert len(v["negative_inventory"]) == len(set(v["negative_inventory"])) == 13
assert len(v["compile_fail_inventory"]) == 2
assert v["real_five_store_fixture_complete"] is False
e=t["evidence_tranches"]["cross_plane_fresh_readback"]
assert e["positive_cases_checked"] == 3 and e["negative_cases_checked"] == 13 and e["compile_fail_cases_checked"] == 2
assert e["same_da_head_and_certificate_sqlite_snapshot"] is True
assert e["terminal_receipts_match_sampled_store_heads"] is True
assert e["cross_plane_readback_consistent_candidate"] is True
for key in ["cross_plane_authority_integration","whole_node_checkpoint_integration","node_process_integration","g2_global_complete","normative_freeze","production_candidate","activation"]: assert e[key] is False
required=set(p["required_files"])
for path in [str(schema),str(vectors),"scripts/ci/check_trnm_poco_cross_plane_readback_v1_boundary.sh"]: assert path in required
PY

python3 - "$CRATE/src/join.rs" trillionnium/crates/trnm-poco-da-v1/src/store.rs <<'PY'
import pathlib, sys
join = pathlib.Path(sys.argv[1]).read_text()
da = pathlib.Path(sys.argv[2]).read_text()
assert ".fresh_certified_batch_readback(batch_id)" in join
assert ".certified_batch(batch_id)" not in join
assert "fresh_certified_batch_readback" in da
method = da.split("pub fn fresh_certified_batch_readback", 1)[1].split("fn fresh_readback_from_connection", 1)[0]
assert "let transaction = connection.transaction()?;" in method
assert "fresh_readback_from_connection(&transaction)" in method
assert "certified_batch_from_connection(&transaction, batch_id)" in method
assert "transaction.rollback()?;" in method
for receipt in ["agent_receipt", "verify_receipt", "mvcc_receipt", "settlement_receipt"]:
    assert f"request.{receipt}.store_id" in join
assert "one or more lifecycle receipts differ from the sampled store identity" in join
PY

tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT
index="$tmp/candidate.index"
GIT_INDEX_FILE="$index" git read-tree HEAD
GIT_INDEX_FILE="$index" git add -- "${INVENTORY[@]}"
GIT_INDEX_FILE="$index" "$GATE" --candidate-index-only >/dev/null

cargo metadata --manifest-path trillionnium/Cargo.toml --locked --offline --no-deps --format-version 1 |
  python3 -c 'import json,sys; assert any(p["name"]=="trnm-poco-cross-plane-readback-v1" for p in json.load(sys.stdin)["packages"])'
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-da-v1 tests::certified_batch_and_da_head_share_one_fresh_sqlite_snapshot -- --exact
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-cross-plane-readback-v1
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-poco-cross-plane-readback-v1 --all-targets -- -D warnings

printf 'PASS: PoCO cross-plane fresh-readback v1 candidate boundary\n'
