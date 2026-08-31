#!/usr/bin/env bash
set -euo pipefail

# Keep the protobuf compiler outside the repository while making the exact
# toolchain reproducible for local and self-hosted gates.  The caller may pass
# an install root; no existing file is overwritten in place.
VERSION="${TRNM_PROTOC_VERSION:-29.3}"
ARCHIVE="protoc-${VERSION}-linux-x86_64.zip"
ARCHIVE_SHA256="3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a"
URL="https://github.com/protocolbuffers/protobuf/releases/download/v${VERSION}/${ARCHIVE}"
INSTALL_ROOT="${1:-${TRNM_PROTOC_INSTALL_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/trnm/protoc-${VERSION}}}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/trnm-protoc.XXXXXX")"

cleanup() {
  rm -rf -- "$WORK_ROOT"
}
trap cleanup EXIT

if [[ "$VERSION" != "29.3" || "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf '%s\n' "checksum-pinned protoc installer supports only Linux x86_64 protoc 29.3" >&2
  exit 2
fi

if [[ -f "$INSTALL_ROOT/bin/protoc" && ! -L "$INSTALL_ROOT/bin/protoc" \
  && "$("$INSTALL_ROOT/bin/protoc" --version 2>/dev/null || true)" == "libprotoc 29.3" ]]; then
  >&2 printf 'protoc_install=already-present path=%s version=29.3 sha256=%s\n' \
    "$INSTALL_ROOT/bin/protoc" "$ARCHIVE_SHA256"
  printf '%s\n' "$INSTALL_ROOT/bin/protoc"
  exit 0
fi

curl --fail --location --retry 3 --retry-all-errors --silent --show-error \
  -A "Trillionnium-CI/1.0" "$URL" --output "$WORK_ROOT/$ARCHIVE"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$WORK_ROOT/$ARCHIVE" \
  | sha256sum --check --strict

mkdir -p "$WORK_ROOT/extract"
unzip -q "$WORK_ROOT/$ARCHIVE" -d "$WORK_ROOT/extract"
candidate="$WORK_ROOT/extract/bin/protoc"
[[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]] || {
  echo "pinned protoc archive did not contain a regular executable bin/protoc" >&2
  exit 2
}
[[ "$("$candidate" --version)" == "libprotoc 29.3" ]] || {
  echo "pinned protoc archive returned an unexpected version" >&2
  exit 2
}

mkdir -p "$(dirname "$INSTALL_ROOT")"
staging="$(mktemp -d "$(dirname "$INSTALL_ROOT")/.protoc-${VERSION}.XXXXXX")"
cleanup_staging() {
  rm -rf -- "$staging"
}
trap cleanup_staging RETURN
mkdir -p "$staging/bin"
install -m 0755 "$candidate" "$staging/bin/protoc"
if [[ -d "$WORK_ROOT/extract/include" ]]; then
  cp -a --no-preserve=mode,ownership "$WORK_ROOT/extract/include" "$staging/include"
fi
if [[ -e "$INSTALL_ROOT" || -L "$INSTALL_ROOT" ]]; then
  # Never replace a non-directory or a symlink; an operator must quarantine it
  # explicitly rather than letting a gate follow an unexpected path.
  [[ -d "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]] || {
    echo "refusing to replace non-directory or symlink protoc install root: $INSTALL_ROOT" >&2
    exit 2
  }
  echo "refusing to replace an existing protoc install root with a mismatched version: $INSTALL_ROOT" >&2
  echo "remove or quarantine that exact cache directory, then retry" >&2
  exit 2
fi
mv -- "$staging" "$INSTALL_ROOT"
trap - RETURN
>&2 printf 'protoc_install=passed path=%s version=29.3 sha256=%s\n' \
  "$INSTALL_ROOT/bin/protoc" "$ARCHIVE_SHA256"
printf '%s\n' "$INSTALL_ROOT/bin/protoc"
