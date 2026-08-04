#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
protoc_bin="${PROTOC:-protoc}"
expected_protoc_version="${POCO_BFT_PROTOC_VERSION:-libprotoc 29.3}"

if ! command -v "$protoc_bin" >/dev/null 2>&1; then
  echo "protoc is required; set PROTOC to a pinned executable" >&2
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
