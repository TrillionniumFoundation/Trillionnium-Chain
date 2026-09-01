#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

production_wal="trillionnium/crates/trnm-poco-node/src/finalization_intent_wal.rs"
deriver="trillionnium/crates/trnm-poco-node/build.rs"
prefix="trillionnium/crates/trnm-poco-node/src/finalization_intent_process_prefix_v1.inc"
helper="trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-finalization-intent-kill-helper.rs"
test_file="trillionnium/crates/trnm-poco-node/tests/finalization_intent_process_kill_matrix.rs"
workflow=".github/workflows/trnm-payload-replay-recovery-v1.yml"
plan="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
modules="docs/development/module-registry-v1.toml"
train="docs/development/release-train-v1.toml"
support=(
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_1.inc
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_2.inc
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_3.inc
  trillionnium/crates/trnm-poco-node/src/finalization_intent_process_support_v1_4.inc
)

for path in "$production_wal" "$deriver" "$prefix" "$helper" "$test_file" \
  "$workflow" "$plan" "$modules" "$train" "${support[@]}"; do
  test -f "$path" || {
    echo "missing G1 finalization source or canonical authority: $path" >&2
    exit 2
  }
done

test "$(uname -s)" = "Linux" || {
  echo "finalization SIGKILL evidence requires Linux" >&2
  exit 2
}

bash scripts/ci/check_canonical_development_plan.sh

# Keep the process fixture byte-derived from the reviewed production WAL. A
# changed production blob requires an explicit source-bound review and gate
# update rather than silently regenerating old documentation metadata.
test "$(git hash-object "$production_wal")" = \
  "017131374d23efecf29142ff14f6e95f79013d27" || {
  echo "production finalization WAL differs from the reviewed source" >&2
  exit 2
}
test "$(wc -c < "$production_wal")" -eq 28263

python3 - "$deriver" "$prefix" "$helper" "$test_file" "$plan" "$modules" "$train" "${support[@]}" <<'PY'
from pathlib import Path
import sys
import tomllib

deriver = Path(sys.argv[1]).read_text(encoding="utf-8")
prefix = Path(sys.argv[2]).read_text(encoding="utf-8")
helper = Path(sys.argv[3]).read_text(encoding="utf-8")
test = Path(sys.argv[4]).read_text(encoding="utf-8")
plan = Path(sys.argv[5]).read_text(encoding="utf-8")
modules = tomllib.loads(Path(sys.argv[6]).read_text(encoding="utf-8"))
train = tomllib.loads(Path(sys.argv[7]).read_text(encoding="utf-8"))
support = "".join(Path(value).read_text(encoding="utf-8") for value in sys.argv[8:])
combined = deriver + prefix + support

for token in (
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
):
    if token not in combined:
        raise SystemExit(f"missing finalization process boundary: {token}")
if "include!(concat!(" not in helper or "finalization_intent_wal_process_v1.rs" not in helper:
    raise SystemExit("helper is not generated from the reviewed WAL")
for token in (
    "CARGO_BIN_EXE_trnm-poco-finalization-intent-kill-helper",
    "bytes[17] ^= 1",
    "marker_links",
    "same_inode",
):
    if token not in test:
        raise SystemExit(f"process test missing retained negative: {token}")
if test.count('"write_') < 3 or test.count('"clear_') < 2:
    raise SystemExit("process test lost required durability cuts")

plan_lower = plan.lower()
for marker in (
    "ordered finalization",
    "crash",
    "physical power",
    "node commit ledger",
    "production_candidate = false",
):
    if marker not in plan_lower:
        raise SystemExit(f"canonical plan missing finalization marker: {marker}")
module_rows = modules.get("module", modules.get("modules", []))
ids = {row.get("id") for row in module_rows if isinstance(row, dict)} if isinstance(module_rows, list) else set()
if not {"M03", "M08", "M15"} <= ids:
    raise SystemExit("module registry is missing finalization/recovery ownership")
train_lower = repr(train).lower()
if "final" not in train_lower or "recovery" not in train_lower:
    raise SystemExit("release train does not retain finalization/recovery blockers")
PY

python3 - <<'PY'
from pathlib import Path
import tomllib

cargo = tomllib.loads(Path("trillionnium/crates/trnm-poco-node/Cargo.toml").read_text(encoding="utf-8"))
if cargo["features"]["default"] != []:
    raise SystemExit("default feature set must remain empty")
metadata = cargo["package"]["metadata"]["trnm"]
for key in (
    "production_candidate",
    "production_consensus_activation",
    "effect_driver_finality_verified",
    "native_application_finality_permit_integration",
    "native_application_recovery_integration",
):
    if metadata[key] is not False:
        raise SystemExit(f"unexpected production truth: {key}")
for key in (
    "finalization_intent_publication_repair_candidate",
    "finalization_intent_process_sigkill_source",
):
    if metadata[key] is not True:
        raise SystemExit(f"missing candidate source marker: {key}")
for key in (
    "finalization_intent_process_sigkill_executed",
    "finalization_process_kill_matrix_complete",
):
    if metadata[key] is not False:
        raise SystemExit(f"unearned process evidence claim: {key}")
PY

export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CARGO_TERM_COLOR=never

cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --manifest-path trillionnium/Cargo.toml --locked \
  --package trnm-poco-node --features lab-validator-runtime-test-support \
  --lib finalization_intent_wal::tests
cargo test --manifest-path trillionnium/Cargo.toml --locked \
  --package trnm-poco-node --features lab-validator-runtime-test-support \
  --test finalization_intent_process_kill_matrix
cargo clippy --manifest-path trillionnium/Cargo.toml --locked \
  --package trnm-poco-node --features lab-validator-runtime-test-support \
  --bin trnm-poco-finalization-intent-kill-helper \
  --test finalization_intent_process_kill_matrix -- -D warnings

bash scripts/check_ci_runner_policy.sh --worktree
bash scripts/check_cargo_offline_policy.sh --worktree
git diff --check
