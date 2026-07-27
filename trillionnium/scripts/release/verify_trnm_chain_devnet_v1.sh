#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <archive.tar.gz> <archive.sha256> <archive.ed25519> <trusted-public-key.pem>" >&2
  exit 64
fi

exec python3 "$script_dir/trnm_chain_devnet_v1.py" verify \
  --archive "$1" \
  --checksum "$2" \
  --signature "$3" \
  --trusted-public-key "$4"
