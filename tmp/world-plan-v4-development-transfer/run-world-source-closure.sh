#!/usr/bin/env bash
set -euo pipefail

world="${1:?world checkout path required}"
control="${2:?control checkout path required}"
export_parent="${3:?export parent required}"

WORLD_HEAD="${WORLD_HEAD:-5605cfb8861aa923f69ff032ddbff7d035bccb0c}"
CONTROL_HEAD="${CONTROL_HEAD:?exact control head required}"
manifest="$world/trillionnium/Cargo.toml"
crate="$world/trillionnium/crates/trnm-game-server"

# Bind every transformation to immutable reviewed inputs.
test "$(git -C "$world" rev-parse HEAD)" = "$WORLD_HEAD"
test "$(git -C "$control" rev-parse HEAD)" = "$CONTROL_HEAD"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/build.rs)" = "abc8d4228123e13a3dc5e3e154467a7d2b67e2ee"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/src/lib.rs)" = "f5b2d91ae359d86fd259dc1b170982b8a0960d13"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/src/lib.rs.in)" = "8882f47db55ca5993329594901c828c6faf325a8"
test "$(git -C "$world" hash-object trillionnium/crates/trnm-game-server/Cargo.toml)" = "d27f7eb6a06bc3b8ceb13e31edacc72d3f58262f"
git -C "$world" apply --check "$control/tmp/world-plan-v4-development-transfer/world-campaign-atomicity.patch"
git -C "$world" apply --check "$control/tmp/world-plan-v4-development-transfer/world-rts-atomicity.patch"

# Execute the old semantic transform exactly once, materialize its result as
# ordinary reviewed source, and remove every compiled template authority.
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
    toolchain.write_text(
        toolchain_text.replace('channel = "stable"', 'channel = "1.98.0"', 1),
        encoding="utf-8",
    )
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

# Apply state-preserving economic and simulation command changes.
git -C "$world" apply "$control/tmp/world-plan-v4-development-transfer/world-campaign-atomicity.patch"
git -C "$world" apply "$control/tmp/world-plan-v4-development-transfer/world-rts-atomicity.patch"

# Migrate source-facing tests and static gates away from retired template paths.
# This changes only the location of reviewed source; it does not relax the
# transaction, settlement, fencing, authority, or fail-closed predicates.
python3 - "$world" <<'PY'
from pathlib import Path
import sys

world = Path(sys.argv[1])
roots = [
    world / "scripts",
    world / "trillionnium/crates/trnm-game-server/tests",
]
replacements = {
    "src/lib.rs.in": "src/lib.rs",
    "settlement_worker.rs.in": "settlement_worker.rs",
}
changed = []
for root in roots:
    if not root.exists():
        continue
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".rs", ".py", ".sh"}:
            continue
        text = path.read_text(encoding="utf-8")
        updated = text
        for old, new in replacements.items():
            updated = updated.replace(old, new)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(str(path.relative_to(world)))
print("direct_source_reference_migrations=" + str(len(changed)))
for path in changed:
    print(path)
PY

cargo fmt --manifest-path "$manifest" --all

# Run direct-source and settlement boundary gates after their source-path
# migration. Any semantic predicate failure remains fatal.
for checker in \
  "$world/scripts/check-trnm-game-server-direct-source.sh" \
  "$world/scripts/check-trnm-settlement-transaction-boundary.sh" \
  "$world/scripts/check_trnm_settlement_transaction_boundary.sh"; do
  if test -f "$checker"; then
    bash "$checker"
  fi
done

# Execute deterministic source and regression gates before any decomposition.
cargo test --manifest-path "$manifest" --locked -p trnm-campaign-core --lib
cargo test --manifest-path "$manifest" --locked -p trnm-rts-sim --lib
cargo test --manifest-path "$manifest" --locked -p trnm-game-server --lib
for test_target in \
  direct_source_bundle \
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

cargo check --manifest-path "$manifest" --locked -p trnm-game-server --all-targets
cargo clippy --manifest-path "$manifest" --locked \
  -p trnm-campaign-core -p trnm-rts-sim -p trnm-game-server \
  --all-targets -- -D warnings
git -C "$world" diff --check

# Export every changed text source exactly as tested. The artifact is the only
# transfer input; its manifest binds path, bytes, Git blob identity and SHA-256.
export_root="$export_parent/world"
rm -rf "$export_parent"
mkdir -p "$export_root"
mapfile -t changed_paths < <(
  git -C "$world" diff --name-only --diff-filter=ACMRTUXB | sort -u
)
for relative in "${changed_paths[@]}"; do
  source_path="$world/$relative"
  test -f "$source_path"
  mkdir -p "$export_root/$(dirname "$relative")"
  cp "$source_path" "$export_root/$relative"
done

git -C "$world" diff --binary > "$export_parent/world.patch"
python3 - "$world" "$export_parent" "$WORLD_HEAD" "$CONTROL_HEAD" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

world = Path(sys.argv[1])
parent = Path(sys.argv[2])
world_head = sys.argv[3]
control_head = sys.argv[4]
root = parent / "world"
files = []
for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    data = path.read_bytes()
    relative = path.relative_to(root)
    files.append({
        "path": str(relative),
        "bytes": len(data),
        "git_blob_sha1": subprocess.check_output(
            ["git", "hash-object", str(path)], text=True
        ).strip(),
        "sha256": hashlib.sha256(data).hexdigest(),
    })
manifest = {
    "schema": "trnm_world_plan_v4_development_transfer_v3",
    "source_world_head": world_head,
    "source_world_tree": subprocess.check_output(
        ["git", "-C", str(world), "rev-parse", "HEAD^{tree}"], text=True
    ).strip(),
    "control_head": control_head,
    "runner_repository": os.environ.get("GITHUB_REPOSITORY", "local"),
    "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
    "rust_toolchain": "1.98.0",
    "deletions": [
        "trillionnium/crates/trnm-game-server/build.rs",
        "trillionnium/crates/trnm-game-server/src/lib.rs.in",
    ],
    "gates": [
        "direct-source-materialization",
        "campaign-error-state-preservation",
        "rts-rejected-command-state-preservation",
        "settlement-transaction-boundary",
        "campaign-core-lib-tests",
        "rts-sim-lib-tests",
        "game-server-lib-and-contract-tests",
        "game-server-all-target-check",
        "strict-clippy",
        "transition-cross-implementation-conformance",
    ],
    "files": files,
}
(parent / "manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

find "$export_parent" -type f -print0 | sort -z | xargs -0 sha256sum > "$export_parent/SHA256SUMS"
