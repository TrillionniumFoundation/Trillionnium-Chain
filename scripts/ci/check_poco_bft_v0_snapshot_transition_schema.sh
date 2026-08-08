#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
node "$repo_root/scripts/ci/check_poco_bft_v0_snapshot_transition_schema.mjs"
