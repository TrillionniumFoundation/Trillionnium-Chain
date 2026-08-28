#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

manifest=trillionnium/Cargo.toml
package=trnm-consensus-peer-lease
recovery_root=trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery

cargo fmt --manifest-path "$manifest" --all -- --check
rustfmt --edition 2021 --check \
  trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery.rs \
  "$recovery_root/part_01_types.rs" \
  "$recovery_root/part_02_owner.rs" \
  "$recovery_root/part_03_wal.rs" \
  "$recovery_root/part_04_io_ack.rs" \
  "$recovery_root/part_05_tests.rs" \
  trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-v1.rs
cargo test --manifest-path "$manifest" --locked -p "$package" -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked -p "$package" --all-targets -- -D warnings

python3 - <<'PY'
from pathlib import Path

manifest = Path("trillionnium/crates/trnm-consensus-peer-lease/Cargo.toml").read_text()
crate_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/lib.rs").read_text()
implementation_root = Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery.rs"
).read_text()
implementation_parts = sorted(Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery"
).glob("part_*.rs"))
if len(implementation_parts) != 5:
    raise SystemExit("payload replay recovery implementation must have five source units")
implementation = implementation_root + "\n" + "\n".join(
    path.read_text() for path in implementation_parts
)
cli = Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/bin/"
    "trnm-payload-replay-recovery-v1.rs"
).read_text()
package = Path(
    "docs/development/packages/"
    "TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md"
).read_text()
workflow = Path(
    ".github/workflows/trnm-payload-replay-recovery-v1.yml"
).read_text()

required_manifest = {
    "payload_replay_external_recovery_owner_candidate = true",
    "payload_replay_core_ack_ledger_candidate = true",
    "payload_replay_core_ack_atomic_with_core = false",
    "payload_replay_recovery_production_activation = false",
    "production_activation = false",
    "production_candidate = false",
}
for value in sorted(required_manifest):
    if value not in manifest:
        raise SystemExit(f"missing Cargo truth flag: {value}")

required_source = {
    "PAYLOAD_REPLAY_EXTERNAL_RECOVERY_OWNER_CANDIDATE_V1",
    "PAYLOAD_REPLAY_CORE_ACK_LEDGER_CANDIDATE_V1",
    "PAYLOAD_REPLAY_CORE_ACK_ATOMIC_WITH_CORE_V1",
    "PayloadReplayRecoveryOwnerV1",
    "PayloadReplayRecoveryTargetV1",
    "PayloadReplayCoreAcknowledgementV1",
    "PayloadReplayRecoveryStatusV1",
}
for value in sorted(required_source):
    if value not in implementation or value not in crate_root:
        raise SystemExit(f"missing public recovery boundary: {value}")

for value in (
    "candidate_only=true",
    "production=false",
    "atomic_with_core=false",
):
    if value not in cli:
        raise SystemExit(f"CLI truth output missing: {value}")

required_workflow = {
    "github.actor == 'ProfAlexQI'",
    "github.triggering_actor == 'ProfAlexQI'",
    "runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]",
    "bash ./scripts/ci/check_payload_replay_recovery_v1.sh",
    '"docs/chain-poco-bft-mainline-20260825"',
    "CARGO_NET_OFFLINE: \"true\"",
}
for value in sorted(required_workflow):
    if value not in workflow:
        raise SystemExit(f"missing recovery workflow boundary: {value}")

for forbidden in (
    "production_candidate=true",
    "production_consensus_activation=true",
    "core_ack_atomic_with_core = true",
):
    if forbidden in manifest or forbidden in package:
        raise SystemExit(f"forbidden promotion wording: {forbidden}")

print("payload replay recovery truth gate: PASS")
PY
