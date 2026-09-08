#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

manifest=trillionnium/Cargo.toml
package=trnm-poco-node
binary=trnm-poco-replay-to-core-coordinator-v1
feature=replay-to-core-coordinator-test-support
source=trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs
operations=config/documentation-operations-v1.json
modules=docs/development/module-registry-v1.toml
train=docs/development/release-train-v1.toml
convergence=config/technical-convergence-v1.toml
workflow=.github/workflows/trnm-replay-to-core-coordinator-v1.yml

for required in "$manifest" "$source" "$operations" "$modules" "$train" "$convergence" "$workflow"; do
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
import json
import tomllib

source = Path("trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs").read_text(encoding="utf-8")
cargo_manifest = Path("trillionnium/crates/trnm-poco-node/Cargo.toml").read_text(encoding="utf-8")
operations = json.loads(Path("config/documentation-operations-v1.json").read_text(encoding="utf-8"))
modules = tomllib.loads(Path("docs/development/module-registry-v1.toml").read_text(encoding="utf-8"))
train = tomllib.loads(Path("docs/development/release-train-v1.toml").read_text(encoding="utf-8"))
convergence = tomllib.loads(Path("config/technical-convergence-v1.toml").read_text(encoding="utf-8"))
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

if operations.get("schema") != "trnm-documentation-operations-v1":
    raise SystemExit("documentation operation registry schema drift")
if operations.get("plan_id") != "trnm-chain-development-plan-v2":
    raise SystemExit("documentation operation registry plan binding drift")
if operations.get("production_authority") is not False:
    raise SystemExit("documentation operation registry must remain non-authoritative")
operation_rows = operations.get("operations", [])
operation_ids = {
    row.get("id") for row in operation_rows if isinstance(row, dict)
}
required_operations = {
    "M02-OP-VOTE-BARRIER",
    "M04-OP-PERSIST-INGRESS",
    "M04-OP-ACK-PREPARED",
    "M08-OP-RECOVER-EXPECTED-LEDGER",
}
if not required_operations <= operation_ids:
    raise SystemExit("operation registry is missing replay-to-Core authority contracts")

module_rows = modules.get("module", modules.get("modules", []))
ids = {
    row.get("id") for row in module_rows if isinstance(row, dict)
} if isinstance(module_rows, list) else set()
if not {"M02", "M03", "M04", "M08", "M15"} <= ids:
    raise SystemExit("module registry does not cover ingress/Core/Safety/recovery/composition ownership")

blocker_rows = train.get("blockers", [])
blocker_ids = {
    row.get("id") for row in blocker_rows if isinstance(row, dict)
}
if not {"NODE-COMMIT-001", "BUILD-CLOSURE-001", "CORE-LIVE-001"} <= blocker_ids:
    raise SystemExit("release train does not retain replay-to-Core blockers")
if "selected_successor" not in repr(train).lower() and "successor" not in repr(train).lower():
    raise SystemExit("release train does not identify the selected successor")

if convergence.get("plan_id") != "trnm-chain-development-plan-v2":
    raise SystemExit("technical convergence plan binding drift")
for flag in (
    "production_authority",
    "production_candidate",
    "production_consensus_activation",
    "public_testnet_ready",
    "release_ready",
    "all_gaps_closed",
):
    if convergence.get(flag) is not False:
        raise SystemExit(f"unexpected convergence promotion: {flag}")
runtime_gaps = set(convergence.get("runtime_gaps", {}).get("ids", []))
if not {"P1-CORE-001", "P2-NODE-001"} <= runtime_gaps:
    raise SystemExit("technical convergence no longer records Core/node integration gaps")

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
