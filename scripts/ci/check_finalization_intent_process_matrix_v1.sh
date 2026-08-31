#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

manifest="docs/development/packages/trnm-g1-r4a-manifest-v1.toml"
doc="docs/development/packages/TRNM_G1_R4A_FINALIZATION_INTENT_PROCESS_MATRIX_V1.md"
production_wal="trillionnium/crates/trnm-poco-node/src/finalization_intent_wal.rs"
deriver="trillionnium/crates/trnm-poco-node/build.rs"
prefix="trillionnium/crates/trnm-poco-node/src/finalization_intent_process_prefix_v1.inc"
helper="trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-finalization-intent-kill-helper.rs"
test_file="trillionnium/crates/trnm-poco-node/tests/finalization_intent_process_kill_matrix.rs"
workflow=".github/workflows/trnm-payload-replay-recovery-v1.yml"
support=(
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_1.inc
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_2.inc
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_3.inc
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_4.inc
)

for path in "$manifest" "$doc" "$production_wal" "$deriver" "$prefix" \
  "$helper" "$test_file" "$workflow" "${support[@]}"; do
  test -f "$path" || {
    echo "missing G1-R4A source: $path" >&2
    exit 1
  }
done

test "$(uname -s)" = "Linux" || {
  echo "G1-R4A SIGKILL evidence requires Linux" >&2
  exit 1
}

# The production WAL must remain byte-identical to the reviewed base. The
# test-only process copy is exact-derived by build.rs and refuses a changed
# byte length or transformation preimage.
test "$(git hash-object "$production_wal")" = \
  "017131374d23efecf29142ff14f6e95f79013d27" || {
  echo "production finalization WAL differs from the reviewed source" >&2
  exit 1
}
test "$(wc -c < "$production_wal")" -eq 28263

python3 - "$manifest" <<'PY'
import pathlib
import sys
import tomllib

path = pathlib.Path(sys.argv[1])
data = tomllib.loads(path.read_text(encoding="utf-8"))
assert data["schema_version"] == 1
assert data["status"] == "source-implemented-execution-unverified"
assert data["base_commit"] == "a259e0b28a2d9dea838f5ceac0e805803ac51dd4"
assert data["base_tree"] == "1715f5f5a614679e1ba45239a7a884c10f7bc5ae"
assert data["production_candidate"] is False
assert data["production_consensus_activation"] is False
assert data["g1_r4_exit"] is False
capabilities = data["capabilities"]
assert capabilities["exact_publication_repair_candidate"] is True
assert capabilities["source_derived_from_production_wal"] is True
assert capabilities["production_wal_byte_identical"] is True
assert capabilities["real_process_sigkill_source"] is True
assert capabilities["real_process_sigkill_executed"] is False
assert capabilities["process_kill_matrix_complete"] is False
assert data["source"]["workflow"] == ".github/workflows/trnm-payload-replay-recovery-v1.yml"
assert data["evidence"]["hosted_workflow"] == "not-run"
assert len(data["cut_matrix"]["write"]) == 3
assert len(data["cut_matrix"]["clear"]) == 2
PY

python3 - "$deriver" "$prefix" "$helper" "$test_file" "${support[@]}" <<'PY'
from pathlib import Path
import sys

deriver = Path(sys.argv[1]).read_text(encoding="utf-8")
prefix = Path(sys.argv[2]).read_text(encoding="utf-8")
helper = Path(sys.argv[3]).read_text(encoding="utf-8")
test = Path(sys.argv[4]).read_text(encoding="utf-8")
support = "".join(Path(value).read_text(encoding="utf-8") for value in sys.argv[5:])
combined = deriver + prefix + support
required = [
    "WAL_BYTES_V1: usize = 28_263",
    "recover_marker_publication_v1",
    "write_temp_fsynced_before_publish",
    "write_published_before_temp_cleanup",
    "write_complete_before_return",
    "clear_unlinked_before_parent_fsync",
    "clear_complete_before_return",
    "run_finalization_intent_kill_helper_v1",
    "published and temporary finalization intent residues conflict",
    "marker_links",
    "same_inode",
]
for token in required:
    assert token in combined, token
assert "include!(concat!(" in helper
assert "finalization_intent_wal_process_v1.rs" in helper
assert "CARGO_BIN_EXE_trnm-poco-finalization-intent-kill-helper" in test
assert "bytes[17] ^= 1" in test
assert "marker_links" in test
assert "same_inode" in test
assert test.count('"write_') >= 3
assert test.count('"clear_') >= 2
PY

# The candidate must remain absent from the default feature set and every
# production/readiness truth must remain false.
python3 - <<'PY'
from pathlib import Path
import tomllib

cargo = tomllib.loads(Path("trillionnium/crates/trnm-poco-node/Cargo.toml").read_text(encoding="utf-8"))
assert cargo["features"]["default"] == []
metadata = cargo["package"]["metadata"]["trnm"]
for key in (
    "production_candidate",
    "production_consensus_activation",
    "effect_driver_finality_verified",
    "native_application_finality_permit_integration",
    "native_application_recovery_integration",
):
    assert metadata[key] is False, key
assert metadata["finalization_intent_publication_repair_candidate"] is True
assert metadata["finalization_intent_process_sigkill_source"] is True
assert metadata["finalization_intent_process_sigkill_executed"] is False
assert metadata["finalization_process_kill_matrix_complete"] is False
PY

export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CARGO_TERM_COLOR=never

cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test \
  --manifest-path trillionnium/Cargo.toml \
  --locked \
  --package trnm-poco-node \
  --features lab-validator-runtime-test-support \
  --lib finalization_intent_wal::tests
cargo test \
  --manifest-path trillionnium/Cargo.toml \
  --locked \
  --package trnm-poco-node \
  --features lab-validator-runtime-test-support \
  --test finalization_intent_process_kill_matrix
cargo clippy \
  --manifest-path trillionnium/Cargo.toml \
  --locked \
  --package trnm-poco-node \
  --features lab-validator-runtime-test-support \
  --bin trnm-poco-finalization-intent-kill-helper \
  --test finalization_intent_process_kill_matrix \
  -- -D warnings

bash scripts/check_ci_runner_policy.sh --worktree
bash scripts/check_cargo_offline_policy.sh --worktree
git diff --check
