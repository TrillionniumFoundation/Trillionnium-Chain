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
  "$recovery_root/part_06_projection.rs" \
  "$recovery_root/part_07_socket.rs" \
  trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-v1.rs \
  trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-owner-v1.rs
cargo test --manifest-path "$manifest" --locked -p "$package" -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked -p "$package" --all-targets -- -D warnings

python3 - <<'PY'
from pathlib import Path

manifest = Path("trillionnium/crates/trnm-consensus-peer-lease/Cargo.toml").read_text()
crate_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/lib.rs").read_text()
payload_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/payload.rs").read_text()
implementation_root = Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery.rs"
).read_text()
implementation_parts = sorted(Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery"
).glob("part_*.rs"))
if len(implementation_parts) != 7:
    raise SystemExit("payload replay recovery implementation must have seven source units")
implementation = implementation_root + "\n" + "\n".join(
    path.read_text() for path in implementation_parts
)
cli = Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/bin/"
    "trnm-payload-replay-recovery-v1.rs"
).read_text()
owner_cli = Path(
    "trillionnium/crates/trnm-consensus-peer-lease/src/bin/"
    "trnm-payload-replay-recovery-owner-v1.rs"
).read_text()
package = Path(
    "docs/development/packages/"
    "TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md"
).read_text()
socket_package = Path(
    "docs/development/packages/TRNM_G1_R1_SOCKET_OWNER_BOUNDARY_V1.md"
).read_text()
socket_test = Path(
    "trillionnium/crates/trnm-consensus-peer-lease/tests/"
    "payload_replay_recovery_owner_socket.rs"
).read_text()
workflow = Path(
    ".github/workflows/trnm-payload-replay-recovery-v1.yml"
).read_text()

required_manifest = {
    "payload_replay_external_recovery_owner_candidate = true",
    "payload_replay_recovery_socket_candidate = true",
    "payload_replay_recovery_socket_peer_credentials = true",
    "payload_replay_recovery_socket_mac = false",
    "payload_replay_recovery_socket_production_activation = false",
    "payload_replay_recovery_socket_client_transport_errors_non_fatal = true",
    "payload_replay_recovery_socket_max_concurrent_connections = 1",
    "payload_replay_core_ack_ledger_candidate = true",
    "payload_replay_core_ack_atomic_with_core = false",
    "payload_replay_recovery_production_activation = false",
    "payload_replay_bounded_wal_replay_memory = true",
    "payload_replay_bounded_temporary_scan = true",
    "payload_replay_generation_overflow_fail_closed = true",
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
    "PayloadReplayRecoveryStatusProjectionV1",
    "PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_SCHEMA_V1",
    "PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_CANDIDATE_V1",
    "PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_PRODUCTION_ACTIVATION_V1",
    "PAYLOAD_REPLAY_RECOVERY_ENDPOINT_IDENTITY_SCHEMA_V1",
    "PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1",
    "PAYLOAD_REPLAY_RECOVERY_SOCKET_CANDIDATE_V1",
    "PAYLOAD_REPLAY_RECOVERY_SOCKET_PRODUCTION_ACTIVATION_V1",
    "PAYLOAD_REPLAY_RECOVERY_SOCKET_CLIENT_TRANSPORT_ERRORS_NON_FATAL_V1",
    "PAYLOAD_REPLAY_RECOVERY_SOCKET_MAX_CONCURRENT_CONNECTIONS_V1",
    "PayloadReplayRecoveryDaemonV1",
    "PayloadReplayRecoveryClientV1",
}
for value in sorted(required_source):
    if value not in implementation or value not in crate_root:
        raise SystemExit(f"missing public recovery boundary: {value}")

required_payload_source = {
    "PAYLOAD_REPLAY_MAX_WAL_BYTES_V1",
    "PAYLOAD_REPLAY_MAX_TEMPORARY_FILES_V1",
    "PAYLOAD_REPLAY_MAX_TEMPORARY_SCAN_ENTRIES_V1",
    "payload_replay_generation_successor_v1",
    "generation_successor_fails_closed_at_u64_max",
    "oversized_payload_wal_is_rejected_before_snapshot_allocation",
    "stale_head_scan_is_bounded_before_directory_fanout",
}
for value in sorted(required_payload_source):
    if value not in payload_root:
        raise SystemExit(f"missing bounded payload replay marker: {value}")

required_recovery_source = {
    "recovery_rejects_oversized_wal_before_snapshot_allocation",
    "recovery_temporary_path_collections_are_bounded",
}
for value in sorted(required_recovery_source):
    if value not in implementation:
        raise SystemExit(f"missing bounded recovery replay marker: {value}")

if any(
    marker in payload_root or marker in implementation
    for marker in (
        "generation.saturating_add(1)",
        "record.generation.saturating_add(1)",
    )
):
    raise SystemExit("generation rollover must use checked successor arithmetic")

for value in (
    "bounded_wal_replay_memory = true",
    "bounded_temporary_scan = true",
    "generation_overflow_fail_closed = true",
):
    if value not in package:
        raise SystemExit(f"package manifest missing bounded replay capability: {value}")

for value in (
    "RecoverySocketConnectionErrorV1",
    "exercise_malformed_client_disconnects",
    "max_concurrent_connections=1",
    "non-fatal connection",
):
    if value not in implementation + socket_test + socket_package:
        raise SystemExit(f"missing recovery socket DoS hardening marker: {value}")

for value in (
    "candidate_only=true",
    "production=false",
    "atomic_with_core=false",
):
    if value not in cli:
        raise SystemExit(f"CLI truth output missing: {value}")

for value in (
    "candidate_only=true",
    "production=false",
    "atomic_with_core=false",
    "trnm.payload-replay-recovery-owner-socket.v1",
):
    if value not in owner_cli:
        raise SystemExit(f"owner CLI truth output missing: {value}")

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
