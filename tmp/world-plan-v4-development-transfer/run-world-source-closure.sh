#!/usr/bin/env bash
set -euo pipefail

world="${1:?world checkout path required}"
control="${2:?control checkout path required}"
export_parent="${3:?export parent required}"

WORLD_HEAD="${WORLD_HEAD:-5605cfb8861aa923f69ff032ddbff7d035bccb0c}"
CONTROL_HEAD="${CONTROL_HEAD:-3246b87b0ea349e691f38355f86567cb8c793ba2}"
manifest="$world/trillionnium/Cargo.toml"
crate="$world/trillionnium/crates/trnm-game-server"

# Bind every transformation to the reviewed input identities.
test "$(git -C "$world" rev-parse HEAD)" = "$WORLD_HEAD"
test "$(git -C "$control" rev-parse HEAD)" = "$CONTROL_HEAD"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/build.rs)" = "abc8d4228123e13a3dc5e3e154467a7d2b67e2ee"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/src/lib.rs)" = "f5b2d91ae359d86fd259dc1b170982b8a0960d13"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/src/lib.rs.in)" = "8882f47db55ca5993329594901c828c6faf325a8"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/Cargo.toml)" = "d27f7eb6a06bc3b8ceb13e31edacc72d3f58262f"
git -C "$world" apply --check "$control/tmp/world-plan-v4-development-transfer/world-campaign-atomicity.patch"
git -C "$world" apply --check "$control/tmp/world-plan-v4-development-transfer/world-rts-atomicity.patch"

# Execute the reviewed semantic transform once, then retire it from the output.
cargo check --manifest-path "$manifest" --locked -p trnm-game-server --lib
generated="$(find "$world/trillionnium/target" -type f -path '*/out/trnm_game_server_lib_generated.rs' -print | head -n 1)"
test -n "$generated"
test -s "$generated"
cp "$generated" /tmp/trnm_game_server_lib_generated.rs
python3 - "$world" <<'PY'
from pathlib import Path
import sys

world = Path(sys.argv[1])
crate = world / "trillionnium/crates/trnm-game-server"
wrapper_path = crate / "src/lib.rs"
wrapper = wrapper_path.read_text(encoding="utf-8")
marker = "// The full reviewed server body is generated from src/lib.rs.in by build.rs."
if wrapper.count(marker) != 1:
    raise SystemExit("reviewed wrapper marker drifted")
header = wrapper.split(marker, 1)[0].rstrip()
generated = Path("/tmp/trnm_game_server_lib_generated.rs").read_text(encoding="utf-8")
if "trnm_game_server_lib_generated.rs" in generated or "include!(concat!(" in generated:
    raise SystemExit("generated body retained recursive generated-source authority")
wrapper_path.write_text(f"{header}\n\n{generated.lstrip()}", encoding="utf-8")

cargo_path = crate / "Cargo.toml"
cargo = cargo_path.read_text(encoding="utf-8")
build_line = 'build = "build.rs"\n'
if cargo.count(build_line) != 1:
    raise SystemExit("build declaration drifted")
cargo_path.write_text(cargo.replace(build_line, "", 1), encoding="utf-8")

cex_path = crate / "src/cex.rs"
cex = cex_path.read_text(encoding="utf-8")
old = (
    '            let host = url.host_str().unwrap_or_default();\n'
    '            let loopback = host.eq_ignore_ascii_case("localhost")\n'
    '                || host\n'
    '                    .parse::<IpAddr>()\n'
    '                    .is_ok_and(|address| address.is_loopback());\n'
)
new = (
    '            let host = url.host_str().unwrap_or_default();\n'
    "            let canonical_host = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.');\n"
    '            let loopback = canonical_host.eq_ignore_ascii_case("localhost")\n'
    '                || canonical_host\n'
    '                    .parse::<IpAddr>()\n'
    '                    .is_ok_and(|address| address.is_loopback());\n'
)
if cex.count(old) == 1:
    cex_path.write_text(cex.replace(old, new, 1), encoding="utf-8")
elif new not in cex:
    raise SystemExit("localhost normalization source shape drifted")

toolchain = world / "rust-toolchain.toml"
toolchain_text = toolchain.read_text(encoding="utf-8")
if 'channel = "stable"' in toolchain_text:
    toolchain.write_text(toolchain_text.replace('channel = "stable"', 'channel = "1.98.0"', 1), encoding="utf-8")
elif 'channel = "1.98.0"' not in toolchain_text:
    raise SystemExit("Rust toolchain source shape drifted")

for obsolete in (crate / "build.rs", crate / "src/lib.rs.in"):
    if not obsolete.is_file():
        raise SystemExit(f"missing obsolete source: {obsolete}")
    obsolete.unlink()
PY

test ! -e "$crate/build.rs"
test ! -e "$crate/src/lib.rs.in"
! grep -q '^build = "build.rs"$' "$crate/Cargo.toml"
! grep -q 'trnm_game_server_lib_generated.rs' "$crate/src/lib.rs"
! grep -q 'reconcile_economy(&state.cex' "$crate/src/lib.rs"
! grep -q 'settle_pending_matches(&settlement_state' "$crate/src/lib.rs"
grep -q 'terminal settlement is owned by trnm-settlement-worker' "$crate/src/lib.rs"
grep -q 'channel = "1.98.0"' "$world/rust-toolchain.toml"

# Apply state-preserving command boundaries and format the ordinary source.
git -C "$world" apply "$control/tmp/world-plan-v4-development-transfer/world-campaign-atomicity.patch"
git -C "$world" apply "$control/tmp/world-plan-v4-development-transfer/world-rts-atomicity.patch"
cargo fmt --manifest-path "$manifest" --all

# Validate behavior before source partitioning so legacy static scanners remain useful.
bash "$world/scripts/check-trnm-settlement-transaction-boundary.sh"
bash "$world/scripts/check_trnm_settlement_transaction_boundary.sh"
cargo test --manifest-path "$manifest" --locked -p trnm-campaign-core --lib
cargo test --manifest-path "$manifest" --locked -p trnm-rts-sim --lib
cargo test --manifest-path "$manifest" --locked -p trnm-game-server --lib
for test_target in \
  settlement_game_server_boundary \
  settlement_fault_model \
  settlement_worker_contract \
  settlement_runtime_v2_contract; do
  if test -f "$crate/tests/${test_target}.rs"; then
    cargo test --manifest-path "$manifest" --locked -p trnm-game-server --test "$test_target"
  fi
done
python3 "$world/scripts/check-trnm-world-transition-conformance.py"
contract="$world/trillionnium/contracts/trnm-world-transition-v1/Cargo.toml"
cargo test --manifest-path "$contract" --locked
cargo clippy --manifest-path "$contract" --all-targets --locked -- -D warnings

# Split the directly compiled code only at item boundaries. Includes remain
# ordinary Git-tracked source; no build-time semantic generation is restored.
partition="$control/tmp/world-plan-v4-development-transfer/partition-large-rust.py"
python3 "$partition" "$world" game-server
python3 "$partition" "$world" campaign
python3 "$partition" "$world" rts
for package in trnm-game-server trnm-campaign-core trnm-rts-sim; do
  test -f "$world/trillionnium/crates/${package}/src/lib_parts/manifest.json"
done
! grep -R -q 'trnm_game_server_lib_generated.rs' \
  "$crate/src/lib.rs" "$crate/src/lib_parts"
git -C "$world" diff --check

# Re-run compilation and invariants against the exact partitioned output.
cargo fmt --manifest-path "$manifest" --all -- --check
cargo test --manifest-path "$manifest" --locked -p trnm-campaign-core --lib
cargo test --manifest-path "$manifest" --locked -p trnm-rts-sim --lib
cargo test --manifest-path "$manifest" --locked -p trnm-game-server --lib
cargo check --manifest-path "$manifest" --locked -p trnm-game-server --all-targets
cargo clippy --manifest-path "$manifest" --locked \
  -p trnm-campaign-core -p trnm-rts-sim -p trnm-game-server \
  --all-targets -- -D warnings
git -C "$world" diff --check

# Export only the tested source paths, plus one Base64 file per output blob.
export_root="$export_parent/world"
encoded_root="$export_parent/world-base64"
rm -rf "$export_root" "$encoded_root"
mkdir -p "$export_root" "$encoded_root"
copy_path() {
  local relative="$1"
  mkdir -p "$export_root/$(dirname "$relative")"
  cp -a "$world/$relative" "$export_root/$relative"
}
copy_path rust-toolchain.toml
copy_path trillionnium/crates/trnm-game-server/Cargo.toml
copy_path trillionnium/crates/trnm-game-server/src/lib.rs
copy_path trillionnium/crates/trnm-game-server/src/cex.rs
copy_path trillionnium/crates/trnm-game-server/src/lib_parts
copy_path trillionnium/crates/trnm-campaign-core/src/lib.rs
copy_path trillionnium/crates/trnm-campaign-core/src/lib_parts
copy_path trillionnium/crates/trnm-rts-sim/src/lib.rs
copy_path trillionnium/crates/trnm-rts-sim/src/lib_parts

python3 - "$export_parent" "$WORLD_HEAD" "$CONTROL_HEAD" <<'PY'
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys

parent = pathlib.Path(sys.argv[1])
world_head = sys.argv[2]
control_head = sys.argv[3]
root = parent / "world"
encoded_root = parent / "world-base64"
files = []
for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    data = path.read_bytes()
    relative = path.relative_to(root)
    encoded = encoded_root / (str(relative) + ".b64")
    encoded.parent.mkdir(parents=True, exist_ok=True)
    encoded.write_text(base64.b64encode(data).decode("ascii") + "\n", encoding="ascii")
    files.append({
        "path": str(relative),
        "bytes": len(data),
        "git_blob_sha1": subprocess.check_output(["git", "hash-object", str(path)], text=True).strip(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "base64_path": str(encoded.relative_to(encoded_root)),
    })
manifest = {
    "schema": "trnm_world_plan_v4_development_transfer_v2",
    "source_world_head": world_head,
    "source_world_tree": subprocess.check_output(
        ["git", "-C", os.environ["WORLD_CHECKOUT"], "rev-parse", "HEAD^{tree}"], text=True
    ).strip(),
    "control_head": control_head,
    "runner_repository": os.environ.get("GITHUB_REPOSITORY", "local"),
    "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
    "rust_toolchain": "1.98.0",
    "deletions": [
        "trillionnium/crates/trnm-game-server/build.rs",
        "trillionnium/crates/trnm-game-server/src/lib.rs.in"
    ],
    "gates": [
        "direct-source-materialization",
        "campaign-error-state-preservation",
        "rts-rejected-command-state-preservation",
        "direct-source-partition",
        "campaign-core-lib-tests",
        "rts-sim-lib-tests",
        "game-server-lib-and-target-tests",
        "game-server-all-target-check",
        "strict-clippy",
        "settlement-transaction-boundary",
        "transition-cross-implementation-conformance"
    ],
    "files": files,
}
manifest_path = root / "manifest.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
encoded_manifest = encoded_root / "manifest.json.b64"
encoded_manifest.write_text(base64.b64encode(manifest_path.read_bytes()).decode("ascii") + "\n", encoding="ascii")
PY

find "$export_parent" -type f -print0 | sort -z | xargs -0 sha256sum > "$export_parent/SHA256SUMS"
