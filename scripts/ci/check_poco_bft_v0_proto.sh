#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
protoc_bin="${PROTOC:-}"
expected_protoc_version="${POCO_BFT_PROTOC_VERSION:-libprotoc 29.3}"

if [[ -z "$protoc_bin" ]]; then
  if command -v protoc >/dev/null 2>&1; then
    protoc_bin="$(command -v protoc)"
  else
    # Local and self-hosted runs use the same checksum-pinned artifact as the
    # workflow.  Set TRNM_PROTOC_AUTO_INSTALL=0 to require an operator-provided
    # PROTOC and keep the old fail-closed behavior.
    if [[ "${TRNM_PROTOC_AUTO_INSTALL:-1}" != "1" ]]; then
      echo "protoc is required; set PROTOC to a pinned executable" >&2
      exit 1
    fi
    protoc_bin="$($repo_root/scripts/ci/install_pinned_protoc.sh)"
  fi
fi

if [[ ! -x "$protoc_bin" || -L "$protoc_bin" ]]; then
  echo "PROTOC must point to a regular executable" >&2
  exit 1
fi

actual_protoc_version="$($protoc_bin --version)"
if [[ "$actual_protoc_version" != "$expected_protoc_version" ]]; then
  echo "unexpected protoc version: $actual_protoc_version" >&2
  echo "expected: $expected_protoc_version" >&2
  echo "set PROTOC to the pinned executable; changing the expected version requires review" >&2
  exit 1
fi

descriptor_dir="$(mktemp -d)"
trap 'rm -r "$descriptor_dir"' EXIT

"$protoc_bin" \
  --fatal_warnings \
  --proto_path="$repo_root/proto" \
  --include_imports \
  --descriptor_set_out="$descriptor_dir/poco-bft-v0.pb" \
  "$repo_root/proto/trnm/poco/bft/v0/common.proto" \
  "$repo_root/proto/trnm/poco/bft/v0/consensus.proto" \
  "$repo_root/proto/trnm/poco/bft/v0/epoch.proto" \
  "$repo_root/proto/trnm/poco/bft/v0/evidence.proto" \
  "$repo_root/proto/trnm/poco/bft/v0/light_client.proto" \
  "$repo_root/proto/trnm/poco/bft/v0/wire.proto" \
  "$repo_root/proto/trnm/poco/v0/consumption_certificate.proto"

if [[ ! -s "$descriptor_dir/poco-bft-v0.pb" ]]; then
  echo "protoc produced an empty descriptor set" >&2
  exit 1
fi

echo "[ok] PoCO-BFT v0 protobuf descriptor compiled with $actual_protoc_version"
