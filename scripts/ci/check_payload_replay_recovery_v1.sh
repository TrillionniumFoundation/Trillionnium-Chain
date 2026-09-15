#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

manifest=trillionnium/Cargo.toml
package=trnm-consensus-peer-lease
recovery_root=trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery
plan=docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md
modules=docs/development/module-registry-v1.toml
train=docs/development/release-train-v1.toml

for required in "$manifest" "$recovery_root" "$plan" "$modules" "$train" config/consensus-mainline.json; do
  [[ -e "$required" ]] || {
    printf 'payload replay recovery gate failed: missing canonical input: %s\n' "$required" >&2
    exit 2
  }
done

bash scripts/ci/check_canonical_development_plan.sh

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
  trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-owner-v1.rs \
  trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-v1.rs
cargo test --manifest-path "$manifest" --locked --offline -p "$package" -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked --offline -p "$package" --all-targets -- -D warnings
# This explicit feature preserves the candidate socket surface without adding
# it to default builds. Socket permission failures remain real gate failures.
cargo test --manifest-path "$manifest" --locked --offline -p "$package" \
  --features candidate-recovery-socket --all-targets -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked --offline -p "$package" \
  --features candidate-recovery-socket --all-targets -- -D warnings

python3 - <<'PY'
from pathlib import Path
import json
import tomllib

cargo = Path("trillionnium/crates/trnm-consensus-peer-lease/Cargo.toml").read_text(encoding="utf-8")
crate_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/lib.rs").read_text(encoding="utf-8")
implementation_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery.rs").read_text(encoding="utf-8")
parts = sorted(Path("trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery").glob("part_*.rs"))
expected_parts = {
    "part_01_types.rs", "part_02_owner.rs", "part_03_wal.rs", "part_04_io_ack.rs",
    "part_05_tests.rs", "part_06_projection.rs", "part_07_socket.rs",
}
if {path.name for path in parts} != expected_parts:
    raise SystemExit("payload replay recovery implementation must have the exact seven source units")
manifest = tomllib.loads(cargo)
features = manifest.get("features", {})
if features.get("default") != [] or features.get("candidate-recovery-socket") != []:
    raise SystemExit("candidate recovery socket must be explicit and add no default dependency")
for kind, name in (
    ("bin", "trnm-payload-replay-recovery-owner-v1"),
    ("test", "payload_replay_recovery_owner_socket"),
):
    targets = [row for row in manifest.get(kind, []) if row.get("name") == name]
    if len(targets) != 1 or targets[0].get("required-features") != ["candidate-recovery-socket"]:
        raise SystemExit(f"candidate recovery socket {kind} lacks its exact feature fence")
socket_guard = '#[cfg(all(unix, feature = "candidate-recovery-socket"))]'
if implementation_root.count(socket_guard) != 2 or socket_guard not in crate_root:
    raise SystemExit("candidate recovery socket module and exports must remain Unix feature-gated")
implementation = implementation_root + "\n" + "\n".join(path.read_text(encoding="utf-8") for path in parts)
cli = Path("trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-v1.rs").read_text(encoding="utf-8")
def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate machine truth member: {key}")
        result[key] = value
    return result

truth = json.loads(Path("config/consensus-mainline.json").read_text(encoding="utf-8"),
                   object_pairs_hook=unique_members)
modules = tomllib.loads(Path("docs/development/module-registry-v1.toml").read_text(encoding="utf-8"))
train = tomllib.loads(Path("docs/development/release-train-v1.toml").read_text(encoding="utf-8"))

for value in {
    "payload_replay_external_recovery_owner_candidate = true",
    "payload_replay_recovery_socket_candidate = true",
    "payload_replay_recovery_socket_production_activation = false",
    "payload_replay_recovery_socket_mac = false",
    "payload_replay_recovery_socket_max_concurrent_connections = 1",
    "payload_replay_core_ack_ledger_candidate = true",
    "payload_replay_core_ack_atomic_with_core = false",
    "payload_replay_recovery_production_activation = false",
    "production_activation = false",
    "production_candidate = false",
}:
    if value not in cargo:
        raise SystemExit(f"missing Cargo truth flag: {value}")

for value in {
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
    "PayloadReplayRecoveryDaemonV1",
    "PayloadReplayRecoveryClientV1",
    "PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1",
}:
    if value not in implementation or value not in crate_root:
        raise SystemExit(f"missing public recovery boundary: {value}")

for value in ("candidate_only=true", "production=false", "atomic_with_core=false"):
    if value not in cli:
        raise SystemExit(f"CLI truth output missing: {value}")

# The canonical plan is already checked above. Its English wording is not
# executable recovery authority; read real Boolean fields, never prose markers.
if not isinstance(truth, dict) or truth.get("stage") != "G1-native-host-incomplete":
    raise SystemExit("payload recovery machine stage changed without acceptance")
for key in ("production_candidate", "production_consensus_activation"):
    if truth.get(key) is not False:
        raise SystemExit(f"machine truth {key} must remain false")

module_rows = modules.get("module", modules.get("modules", []))
ids = {row.get("id") for row in module_rows if isinstance(row, dict)} if isinstance(module_rows, list) else set()
if not {"M02", "M03", "M04", "M08", "M15"} <= ids:
    raise SystemExit("module registry lacks recovery producer/consumer ownership")

for key in ("production_candidate", "production_consensus_activation", "public_testnet_ready", "release_ready"):
    if train.get(key) is not False:
        raise SystemExit(f"release train {key} must remain false")

for forbidden in (
    "production_candidate=true",
    "production_consensus_activation=true",
    "core_ack_atomic_with_core = true",
):
    if forbidden in cargo or forbidden in implementation:
        raise SystemExit(f"forbidden promotion wording: {forbidden}")

print("payload replay recovery metadata: PASS; machine flags remain false; canonical plan checked separately")
PY

git diff --check
