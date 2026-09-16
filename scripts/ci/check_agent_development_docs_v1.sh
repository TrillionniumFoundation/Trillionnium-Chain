#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

# Compatibility entry point retained for existing workflows. It validates the
# sole Plan v2 and its machine companions; the retired agent/package document
# fleet is forbidden rather than reconstructed.
bash scripts/ci/check_canonical_development_plan.sh
printf '%s\n' 'development truth gate: PASS; one Plan v2, 18 modules, zero active legacy document consumers'
