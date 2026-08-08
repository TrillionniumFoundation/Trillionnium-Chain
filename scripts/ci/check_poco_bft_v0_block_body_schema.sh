#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec node "${script_dir}/check_poco_bft_v0_block_body_schema.mjs"
