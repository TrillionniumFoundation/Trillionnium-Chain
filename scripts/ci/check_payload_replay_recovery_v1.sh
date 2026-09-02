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

for required in "$manifest" "$recovery_root" "$plan" "$modules" "$train"; do
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
  trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-v1.rs
cargo test --manifest-path "$manifest" --locked -p "$package" -- --test-threads=1
cargo clippy --manifest-path "$manifest" --locked -p "$package" --all-targets -- -D warnings

python3 - <<'PY'
from pathlib import Path
import tomllib

cargo = Path("trillionnium/crates/trnm-consensus-peer-lease/Cargo.toml").read_text(encoding="utf-8")
crate_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/lib.rs").read_text(encoding="utf-8")
implementation_root = Path("trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery.rs").read_text(encoding="utf-8")
parts = sorted(Path("trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery").glob("part_*.rs"))
if len(parts) != 6:
    raise SystemExit("payload replay recovery implementation must have six source units")
implementation = implementation_root + "\n" + "\n".join(path.read_text(encoding="utf-8") for path in parts)
cli = Path("trillionnium/crates/trnm-consensus-peer-lease/src/bin/trnm-payload-replay-recovery-v1.rs").read_text(encoding="utf-8")
plan = Path("docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md").read_text(encoding="utf-8")
modules = tomllib.loads(Path("docs/development/module-registry-v1.toml").read_text(encoding="utf-8"))
train = tomllib.loads(Path("docs/development/release-train-v1.toml").read_text(encoding="utf-8"))

for value in {
    "payload_replay_external_recovery_owner_candidate = true",
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
}:
    if value not in implementation or value not in crate_root:
        raise SystemExit(f"missing public recovery boundary: {value}")

for value in ("candidate_only=true", "production=false", "atomic_with_core=false"):
    if value not in cli:
        raise SystemExit(f"CLI truth output missing: {value}")

plan_lower = plan.lower()
for marker in ("payload replay", "node commit ledger", "exact source", "production_candidate = false"):
    if marker not in plan_lower:
        raise SystemExit(f"canonical plan missing recovery marker: {marker}")

module_rows = modules.get("module", modules.get("modules", []))
if not isinstance(module_rows, list) or not any(row.get("id") in {"M04", "M08"} for row in module_rows if isinstance(row, dict)):
    raise SystemExit("module registry does not assign payload/recovery authority")

encoded_train = repr(train).lower()
for marker in ("production_candidate", "production_consensus_activation"):
    if marker not in encoded_train or "false" not in encoded_train:
        raise SystemExit(f"release train missing fail-closed marker: {marker}")

for forbidden in (
    "production_candidate=true",
    "production_consensus_activation=true",
    "core_ack_atomic_with_core = true",
):
    if forbidden in cargo or forbidden in implementation:
        raise SystemExit(f"forbidden promotion wording: {forbidden}")

print("payload replay recovery truth gate: PASS; canonical Plan v2 is the only documentation authority")
PY

git diff --check
