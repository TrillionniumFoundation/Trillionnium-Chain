#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

bash scripts/ci/check_g3_g5_source_binding_v2.sh
bash scripts/ci/check_benchmark_security_ops_contract_v1.sh
bash scripts/ci/check_claim_activation_gate_v2.sh

git diff --check
