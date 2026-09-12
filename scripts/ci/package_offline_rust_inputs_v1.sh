#!/usr/bin/env bash
# Diagnostic build inputs only. Never an execution or release attestation.
set -euo pipefail

[[ $# -eq 1 ]] || { echo 'usage: package_offline_rust_inputs_v1.sh OUTPUT_DIRECTORY' >&2; exit 2; }
root=$(git rev-parse --show-toplevel)
cd "$root"
[[ "${TRNM_EXPECTED_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git rev-parse HEAD)" == "$TRNM_EXPECTED_SOURCE_SHA" ]]
git diff --exit-code HEAD -- .
[[ -z "$(git ls-files --others --exclude-standard)" ]]

# Cargo's vendor directory contains dependency sources, never a copy of the
# runner's Cargo home, registry credentials, environment, caches, or workspaces.
# Refuse any non-public registry or Git dependency before materialization.
python3 - <<'PY'
import pathlib
import tomllib
lock = tomllib.loads(pathlib.Path('trillionnium/Cargo.lock').read_text())
for package in lock['package']:
    source = package.get('source')
    if source is not None and source != 'registry+https://github.com/rust-lang/crates.io-index':
        raise SystemExit('offline inputs refuse a non-crates.io dependency source')
PY

output=$(realpath -m -- "$1")
case "$output/" in "$root/"*) echo 'output must be outside the checkout' >&2; exit 2 ;; esac
[[ ! -e "$output" && ! -L "$output" ]]
mkdir -m 700 -- "$output"
staging=$(mktemp -d "${RUNNER_TEMP:?}/trnm-offline-vendor.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT

rustc=$(rustup which --toolchain 1.95.0 rustc)
cargo=$(rustup which --toolchain 1.95.0 cargo)
sysroot=$("$rustc" --print sysroot)
"$rustc" -Vv > "$output/rustc-version.txt"
"$cargo" -V > "$output/cargo-version.txt"
grep -Fx 'release: 1.95.0' "$output/rustc-version.txt"
grep -Fx 'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860' "$output/rustc-version.txt"
grep -Fx 'host: x86_64-unknown-linux-gnu' "$output/rustc-version.txt"

# The minimal rustup sysroot contains only the public compiler/components and
# their licenses. No parent of the sysroot is archived.
[[ -x "$sysroot/bin/rustc" && -x "$sysroot/bin/cargo" ]]
timeout --signal=TERM --kill-after=10s 600s "$cargo" vendor --locked --versioned-dirs \
  --manifest-path trillionnium/Cargo.toml "$staging/vendor" > "$output/vendor-config-original.toml"
python3 - "$output/vendor-config-original.toml" "$output/vendor-config.toml" <<'PY'
import pathlib
import sys
import tomllib
config = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(config) == {'source'}
assert set(config['source']) == {'crates-io', 'vendored-sources'}
assert config['source']['crates-io'] == {'replace-with': 'vendored-sources'}
assert set(config['source']['vendored-sources']) == {'directory'}
pathlib.Path(sys.argv[2]).write_text(
    '[source.crates-io]\nreplace-with = "vendored-sources"\n'
    '[source.vendored-sources]\ndirectory = "vendor"\n')
PY
# Do not expose a runner-local path in the public artifact.
rm -- "$output/vendor-config-original.toml"
tar -C "$sysroot" -I 'zstd -T2 -3' -cf "$output/rust-1.95.0-x86_64-unknown-linux-gnu.tar.zst" .
tar -C "$staging" -I 'zstd -T2 -3' -cf "$output/crates-io-vendor.tar.zst" vendor
cp trillionnium/Cargo.lock "$output/Cargo.lock"
git rev-parse HEAD > "$output/HEAD"
git rev-parse 'HEAD^{tree}' > "$output/TREE"
printf '%s\n' 'scope=offline-build-inputs-only; tests-not-attested; no-acceptance-or-activation' > "$output/SCOPE"
(cd "$output" && sha256sum -- Cargo.lock HEAD TREE SCOPE rustc-version.txt cargo-version.txt vendor-config.toml *.tar.zst > SHA256SUMS)
git diff --exit-code HEAD -- .
[[ -z "$(git ls-files --others --exclude-standard)" ]]
