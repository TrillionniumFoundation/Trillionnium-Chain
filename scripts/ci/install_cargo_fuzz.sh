#!/usr/bin/env bash
set -euo pipefail

VERSION="0.13.2"
ANYHOW_VERSION="1.0.103"
ARCHIVE="cargo-fuzz-${VERSION}.crate"
ARCHIVE_SHA256="5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2"
PATCHED_LOCK_SHA256="ff29da6d718a5dbfef003d57a6b768f70cdbea6fa309879c90b90a2cd9a2d68c"
URL="https://static.crates.io/crates/cargo-fuzz/${ARCHIVE}"
TOOLCHAIN="${TRNM_FUZZ_TOOLCHAIN:-nightly-2026-07-27}"
INSTALL_ROOT="${1:-${TRNM_CARGO_FUZZ_INSTALL_ROOT:-$HOME/.cargo}}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trnm-cargo-fuzz.XXXXXX")"

cleanup() {
  rm -rf -- "$WORK_ROOT"
}
trap cleanup EXIT

curl --fail --location --retry 3 --silent --show-error \
  -A "Trillionnium-CI/1.0" "$URL" --output "$WORK_ROOT/$ARCHIVE"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$WORK_ROOT/$ARCHIVE" \
  | sha256sum --check --strict

tar -xzf "$WORK_ROOT/$ARCHIVE" -C "$WORK_ROOT"
SOURCE_ROOT="$WORK_ROOT/cargo-fuzz-${VERSION}"
cargo +"$TOOLCHAIN" update --manifest-path "$SOURCE_ROOT/Cargo.toml" \
  --package anyhow --precise "$ANYHOW_VERSION"
printf '%s  %s\n' "$PATCHED_LOCK_SHA256" "$SOURCE_ROOT/Cargo.lock" \
  | sha256sum --check --strict

cargo +"$TOOLCHAIN" install --path "$SOURCE_ROOT" --locked --force \
  --root "$INSTALL_ROOT"
test "$("$INSTALL_ROOT/bin/cargo-fuzz" --version)" = "cargo-fuzz $VERSION"
printf 'cargo_fuzz_install=passed version=%s source_sha256=%s lock_sha256=%s\n' \
  "$VERSION" "$ARCHIVE_SHA256" "$PATCHED_LOCK_SHA256"
