#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

manifest=trillionnium/Cargo.toml
package=trnm-poco-node
binary=trnm-poco-replay-to-core-coordinator-v1
feature=replay-to-core-coordinator-test-support
source=trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs
package_doc=docs/development/packages/TRNM_G1_REPLAY_TO_CORE_DURABLE_ACK_EXECUTION_PACKAGE_V1.md
package_manifest=docs/development/packages/trnm-g1-r2-manifest-v1.toml
workflow=.github/workflows/trnm-replay-to-core-coordinator-v1.yml

rustfmt --edition 2021 --check "$source"
cargo test --manifest-path "$manifest" --locked \
  -p "$package" --features "$feature" --bin "$binary" -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked \
  -p "$package" --features "$feature" --bin "$binary" -- -D warnings

# G1-R2A is stacked on G1-R1.  Its gate must never replace or suppress the
# parent recovery/ack gate.
bash scripts/ci/check_payload_replay_recovery_v1.sh

python3 - <<'PY'
from pathlib import Path

source = Path(
    "trillionnium/crates/trnm-poco-node/src/bin/"
    "trnm-poco-replay-to-core-coordinator-v1.rs"
).read_text()
package_doc = Path(
    "docs/development/packages/"
    "TRNM_G1_REPLAY_TO_CORE_DURABLE_ACK_EXECUTION_PACKAGE_V1.md"
).read_text()
manifest = Path(
    "docs/development/packages/trnm-g1-r2-manifest-v1.toml"
).read_text()
workflow = Path(
    ".github/workflows/trnm-replay-to-core-coordinator-v1.yml"
).read_text()
cargo_manifest = Path("trillionnium/crates/trnm-poco-node/Cargo.toml").read_text()

required_cargo = {
    "replay-to-core-coordinator-test-support = [",
    '"dep:rustix"',
    '"dep:trnm-consensus-peer-lease"',
    'name = "trnm-poco-replay-to-core-coordinator-v1"',
    'required-features = ["replay-to-core-coordinator-test-support"]',
}
for value in sorted(required_cargo):
    if value not in cargo_manifest:
        raise SystemExit(f"missing R2A Cargo target boundary: {value}")

required_source = {
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
}
for value in sorted(required_source):
    if value not in source:
        raise SystemExit(f"missing G1-R2A source boundary: {value}")

# The durable receipt constructor must not be public, and the only production
# authority remains sealed without a concrete live implementation.
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
        raise SystemExit(f"forbidden G1-R2A authority claim: {forbidden}")

required_manifest = {
    'parent_package_status = "candidate-implemented-unverified"',
    "pending_before_core = true",
    "sealed_core_authority_trait = true",
    "public_core_receipt_constructor = false",
    "live_core_adapter = false",
    "core_ack_generated_by_core = false",
    "core_ack_atomic_with_core = false",
    "node_process_integration = false",
    "production_activation = false",
    "g1_r2_exit = false",
}
for value in sorted(required_manifest):
    if value not in manifest:
        raise SystemExit(f"missing G1-R2 manifest truth: {value}")

required_doc = {
    "R2-A — Node-owned recoverable delivery coordinator",
    "R2-B — real Core adapter and process integration",
    "core_adapter_present=false",
    "core_ack_generated_by_core=false",
    "core_ack_atomic_with_core=false",
    "node_process_integration=false",
    "production_activation=false",
}
for value in sorted(required_doc):
    if value not in package_doc:
        raise SystemExit(f"missing G1-R2 package boundary: {value}")

required_workflow = {
    "github.actor == 'ProfAlexQI'",
    "github.triggering_actor == 'ProfAlexQI'",
    "runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]",
    "bash ./scripts/ci/check_replay_to_core_coordinator_v1.sh",
    "CARGO_NET_OFFLINE: \"true\"",
}
for value in sorted(required_workflow):
    if value not in workflow:
        raise SystemExit(f"missing G1-R2 workflow boundary: {value}")

print("G1-R2A replay-to-Core coordinator truth gate: PASS")
PY
