#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

manifest=trillionnium/Cargo.toml
package=trnm-poco-node
binary=trnm-poco-replay-to-core-coordinator-v1
feature=replay-to-core-coordinator-test-support
source=trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs
plan=docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
modules=docs/development/module-registry-v1.toml
train=docs/development/release-train-v1.toml
workflow=.github/workflows/trnm-replay-to-core-coordinator-v1.yml

for required in "$manifest" "$source" "$plan" "$modules" "$train" "$workflow"; do
  [[ -f "$required" && ! -L "$required" ]] || {
    printf 'replay-to-Core coordinator gate failed: missing regular input: %s\n' "$required" >&2
    exit 2
  }
done

bash scripts/ci/check_canonical_development_plan.sh
rustfmt --edition 2021 --check "$source"
cargo test --manifest-path "$manifest" --locked \
  -p "$package" --features "$feature" --bin "$binary" -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked \
  -p "$package" --features "$feature" --bin "$binary" -- -D warnings
bash scripts/ci/check_payload_replay_recovery_v1.sh

python3 - <<'PY'
from pathlib import Path
import tomllib

source = Path("trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs").read_text(encoding="utf-8")
cargo_manifest = Path("trillionnium/crates/trnm-poco-node/Cargo.toml").read_text(encoding="utf-8")
plan = Path("docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md").read_text(encoding="utf-8")
modules = tomllib.loads(Path("docs/development/module-registry-v1.toml").read_text(encoding="utf-8"))
train = tomllib.loads(Path("docs/development/release-train-v1.toml").read_text(encoding="utf-8"))
workflow = Path(".github/workflows/trnm-replay-to-core-coordinator-v1.yml").read_text(encoding="utf-8")

for value in {
    "replay-to-core-coordinator-test-support = [",
    '"dep:rustix"',
    '"dep:trnm-consensus-peer-lease"',
    'name = "trnm-poco-replay-to-core-coordinator-v1"',
    'required-features = ["replay-to-core-coordinator-test-support"]',
}:
    if value not in cargo_manifest:
        raise SystemExit(f"missing replay-to-Core Cargo boundary: {value}")

for value in {
    "REPLAY_TO_CORE_PENDING_BEFORE_CORE_V1: bool = true",
    "REPLAY_TO_CORE_SEALED_AUTHORITY_V1: bool = true",
    "REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = false",
    "REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = false",
    "REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = false",
    "REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = false",
    "REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = false",
    "trait ReplayToCoreAuthorityV1: sealed::SealedReplayToCoreAuthorityV1",
    "fn new_after_durable_core(",
    "self.ensure_pending(request)?;",
    ".deliver_durably(request)",
    ".acknowledge_core(acknowledgement)",
    "self.publish_completed(request, completed)?;",
    "EarlierDeliveryPending",
    "AmbiguousPublication",
}:
    if value not in source:
        raise SystemExit(f"missing replay-to-Core source boundary: {value}")

for forbidden in (
    "pub fn new_after_durable_core",
    "pub(crate) fn new_after_durable_core",
    "REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = true",
    "REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = true",
    "REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = true",
    "REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = true",
    "REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = true",
):
    if forbidden in source:
        raise SystemExit(f"forbidden replay-to-Core authority claim: {forbidden}")

plan_lower = plan.lower()
for marker in ("node commit ledger", "crash convergence", "exact source", "production_candidate = false"):
    if marker not in plan_lower:
        raise SystemExit(f"canonical plan missing coordinator marker: {marker}")

module_rows = modules.get("module", modules.get("modules", []))
ids = {row.get("id") for row in module_rows if isinstance(row, dict)} if isinstance(module_rows, list) else set()
if not {"M02", "M03", "M08", "M15"} <= ids:
    raise SystemExit("module registry does not cover Core/Safety/recovery/composition ownership")

if "selected_successor" not in repr(train).lower() and "successor" not in repr(train).lower():
    raise SystemExit("release train does not identify the selected successor")
for value in (
    "check_canonical_development_plan.sh",
    "check_replay_to_core_coordinator_v1.sh",
    "TRNM_EXPECTED_SOURCE_SHA",
):
    if value not in workflow:
        raise SystemExit(f"workflow missing current authority hook: {value}")

print("replay-to-Core coordinator truth gate: PASS; retired package prose is not an authority input")
PY

git diff --check
