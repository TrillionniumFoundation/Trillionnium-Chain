#!/usr/bin/env bash
set -euo pipefail

VERSION="0.20.2"
ARCHIVE="cargo-deny-${VERSION}-x86_64-unknown-linux-musl.tar.gz"
SHA256="9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f"
URL="https://github.com/EmbarkStudios/cargo-deny/releases/download/${VERSION}/${ARCHIVE}"
INSTALL_DIR="${1:-${TRNM_CARGO_DENY_INSTALL_DIR:-$HOME/.local/bin}}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trnm-cargo-deny.XXXXXX")"

cleanup() {
  rm -rf -- "$WORK_ROOT"
}
trap cleanup EXIT

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf '%s\n' "checksum-pinned cargo-deny installer supports Linux x86_64 only" >&2
  exit 2
fi

curl --fail --location --retry 3 --silent --show-error \
  "$URL" --output "$WORK_ROOT/$ARCHIVE"
printf '%s  %s\n' "$SHA256" "$WORK_ROOT/$ARCHIVE" \
  | sha256sum --check --strict

mkdir -p "$WORK_ROOT/extract" "$INSTALL_DIR"
tar -xzf "$WORK_ROOT/$ARCHIVE" -C "$WORK_ROOT/extract"
mapfile -t binaries < <(find "$WORK_ROOT/extract" -type f -name cargo-deny -perm -u+x)
if [[ "${#binaries[@]}" -ne 1 ]]; then
  printf 'expected one cargo-deny binary, found %s\n' "${#binaries[@]}" >&2
  exit 2
fi
install -m 0755 "${binaries[0]}" "$INSTALL_DIR/cargo-deny"
test "$("$INSTALL_DIR/cargo-deny" --version)" = "cargo-deny $VERSION"
printf 'cargo_deny_install=passed version=%s sha256=%s\n' "$VERSION" "$SHA256"
