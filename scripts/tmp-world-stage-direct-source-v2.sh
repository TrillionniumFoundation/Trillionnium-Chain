#!/usr/bin/env bash
set -euo pipefail

readonly WORLD_HEAD="2b3a71c34fcbe9b8dac51826d70e65c4553cbba7"
readonly RUST_TOOLCHAIN="1.98.0"
readonly STAGE_DIR="transport/world-direct-source-${WORLD_HEAD}"
readonly WORLD_DIR="world"
readonly GAME_SERVER="${WORLD_DIR}/trillionnium/crates/trnm-game-server"

cd "${GITHUB_WORKSPACE}"

test "$(git -C "${WORLD_DIR}" rev-parse HEAD)" = "${WORLD_HEAD}"
test "$(git -C "${WORLD_DIR}" hash-object trillionnium/crates/trnm-game-server/build.rs)" = "abc8d4228123e13a3dc5e3e154467a7d2b67e2ee"
test "$(git -C "${WORLD_DIR}" hash-object trillionnium/crates/trnm-game-server/src/lib.rs)" = "f5b2d91ae359d86fd259dc1b170982b8a0960d13"
test "$(git -C "${WORLD_DIR}" hash-object trillionnium/crates/trnm-game-server/src/lib.rs.in)" = "8882f47db55ca5993329594901c828c6faf325a8"
test "$(git -C "${WORLD_DIR}" hash-object trillionnium/crates/trnm-game-server/src/cex.rs)" = "4b8c9d6618d8eff167a5048192f6431e0427a6f0"
test "$(git -C "${WORLD_DIR}" hash-object trillionnium/crates/trnm-game-server/Cargo.toml)" = "d27f7eb6a06bc3b8ceb13e31edacc72d3f58262f"
test -z "$(git -C "${WORLD_DIR}" status --porcelain)"

# Only after immutable source identity and a clean checkout are proven may the
# direct-source boundary tests be materialized in the disposable checkout.
python3 scripts/tmp-world-retire-generator-contracts-v2.py "${WORLD_DIR}"

rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --component rustfmt,clippy
rustup default "${RUST_TOOLCHAIN}"
rustc --version --verbose
cargo --version --verbose

cargo check --manifest-path "${WORLD_DIR}/trillionnium/Cargo.toml" --locked -p trnm-game-server --lib
generated="$(find "${WORLD_DIR}/trillionnium/target" -type f -path '*/out/trnm_game_server_lib_generated.rs' -print | head -n 1)"
test -n "${generated}"
test -s "${generated}"
cp "${generated}" /tmp/trnm_game_server_lib_generated.rs

python3 - <<'PY'
from pathlib import Path

crate = Path("world/trillionnium/crates/trnm-game-server")
lib = crate / "src/lib.rs"
wrapper = lib.read_text(encoding="utf-8")
marker = "// The full reviewed server body is generated from src/lib.rs.in by build.rs."
if wrapper.count(marker) != 1:
    raise SystemExit("reviewed lib.rs wrapper marker drifted")
header = wrapper.split(marker, 1)[0].rstrip()
generated = Path("/tmp/trnm_game_server_lib_generated.rs").read_text(encoding="utf-8")
for forbidden in (
    "trnm_game_server_lib_generated.rs",
    "reconcile_economy(&state.cex",
    "settle_pending_matches(&settlement_state",
):
    if forbidden in generated:
        raise SystemExit(f"materialized body retained forbidden source authority: {forbidden}")
lib.write_text(f"{header}\n\n{generated.lstrip()}", encoding="utf-8")

manifest = crate / "Cargo.toml"
cargo = manifest.read_text(encoding="utf-8")
build_line = 'build = "build.rs"\n'
if cargo.count(build_line) != 1:
    raise SystemExit("Cargo build-script declaration drifted")
manifest.write_text(cargo.replace(build_line, "", 1), encoding="utf-8")

for obsolete in (crate / "build.rs", crate / "src/lib.rs.in"):
    if not obsolete.is_file():
        raise SystemExit(f"missing obsolete source: {obsolete}")
    obsolete.unlink()

cex = crate / "src/cex.rs"
source = cex.read_text(encoding="utf-8")
old = '''            let host = url.host_str().unwrap_or_default();
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
'''
new = '''            let host = url.host_str().unwrap_or_default();
            // Normalize presentation-only DNS root dots and IPv6 brackets before
            // deciding whether plaintext transport is confined to loopback.
            let canonical_host = host
                .trim_end_matches('.')
                .trim_start_matches('[')
                .trim_end_matches(']');
            let loopback = canonical_host.eq_ignore_ascii_case("localhost")
                || canonical_host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
'''
if source.count(old) != 1:
    raise SystemExit("CEX loopback source drifted")
source = source.replace(old, new, 1)
anchor = '''        assert_eq!(
            normalize_service_base_url("http://localhost:8080", "TEST_URL").unwrap(),
            "http://localhost:8080"
        );
'''
extra = '''        for loopback in [
            "http://LOCALHOST:8080/",
            "http://localhost.:8080/",
            "http://[0:0:0:0:0:0:0:1]:8080/",
        ] {
            assert!(
                normalize_service_base_url(loopback, "TEST_URL").is_ok(),
                "unexpectedly rejected loopback endpoint {loopback}"
            );
        }
'''
if source.count(anchor) != 1:
    raise SystemExit("CEX loopback test anchor drifted")
cex.write_text(source.replace(anchor, anchor + extra, 1), encoding="utf-8")
PY

cargo fmt --manifest-path "${WORLD_DIR}/trillionnium/Cargo.toml" -p trnm-game-server
cargo check --manifest-path "${WORLD_DIR}/trillionnium/Cargo.toml" --locked -p trnm-game-server --lib
cargo test --manifest-path "${WORLD_DIR}/trillionnium/Cargo.toml" --locked -p trnm-game-server --lib
cargo clippy --manifest-path "${WORLD_DIR}/trillionnium/Cargo.toml" --locked -p trnm-game-server --lib -- -D warnings
bash "${WORLD_DIR}/scripts/check-trnm-game-server-direct-source.sh"
bash "${WORLD_DIR}/scripts/check-trnm-settlement-transaction-boundary.sh"
bash "${WORLD_DIR}/scripts/check_trnm_settlement_transaction_boundary.sh"
git -C "${WORLD_DIR}" diff --check

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"
cp "${GAME_SERVER}/src/lib.rs" "${STAGE_DIR}/lib.rs"
cp "${GAME_SERVER}/src/cex.rs" "${STAGE_DIR}/cex.rs"
cp "${GAME_SERVER}/Cargo.toml" "${STAGE_DIR}/Cargo.toml"
printf '%s\n' \
  'trillionnium/crates/trnm-game-server/build.rs' \
  'trillionnium/crates/trnm-game-server/src/lib.rs.in' \
  > "${STAGE_DIR}/deleted-files.txt"

STAGE_DIR="${STAGE_DIR}" WORLD_HEAD="${WORLD_HEAD}" RUST_TOOLCHAIN="${RUST_TOOLCHAIN}" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

stage = Path(os.environ["STAGE_DIR"])
files = {}
for name in ("lib.rs", "cex.rs", "Cargo.toml", "deleted-files.txt"):
    data = stage.joinpath(name).read_bytes()
    files[name] = {
        "bytes": len(data),
        "git_blob_sha1": hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
record = {
    "contract": "trnm_world_direct_source_transport_v2",
    "world_head": os.environ["WORLD_HEAD"],
    "rust_toolchain": os.environ["RUST_TOOLCHAIN"],
    "validation": {
        "cargo_check_lib": "passed",
        "cargo_test_lib": "passed",
        "cargo_clippy_deny_warnings": "passed",
        "direct_source_gate": "passed",
        "settlement_transaction_boundaries": "passed",
        "diff_check": "passed",
    },
    "files": files,
    "release_credit": "none",
}
stage.joinpath("manifest.json").write_text(
    json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8"
)
PY
sha256sum "${STAGE_DIR}"/* > "${STAGE_DIR}/SHA256SUMS"
cat "${STAGE_DIR}/manifest.json"

git config user.name github-actions[bot]
git config user.email 41898282+github-actions[bot]@users.noreply.github.com
git add "${STAGE_DIR}"
if git diff --cached --quiet; then
  echo "transport payload already current"
  exit 0
fi
git commit -m "chore(transport): stage validated World direct source [skip ci]"
git push origin HEAD:refs/heads/tmp/world-source-materializer-20260830
