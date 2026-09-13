#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
node "$repo_root/scripts/ci/author_poco_bft_v0_application_sequences.mjs" self-test
node "$repo_root/scripts/ci/check_poco_bft_v0_application_authority_schema.mjs"
