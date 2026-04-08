#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/p1-rust-sidecar.yml"

required_paths=(
  "scripts/v2/run_p1_integration_gate.sh"
  "scripts/v2/run_p1_integration_gate_*_invocation_test.sh"
  "scripts/v2/x2_settlement_contract_gate.sh"
  "scripts/v2/i2_token_lifecycle_gate.sh"
  "scripts/v2/product_layer_smoke.sh"
  "examples/sdk-js/**"
  "trillionnium/crates/trnm-rpc/src/**"
  "trillionnium/crates/trnm-rpc/tests/**"
  ".github/workflows/p1-rust-sidecar.yml"
)

for p in "${required_paths[@]}"; do
  if ! grep -Fq -- "- '$p'" "$WF"; then
    echo "[P1-SIDECAR-PATHS][FAIL] missing workflow trigger path: $p" >&2
    exit 1
  fi
done

echo "[P1-SIDECAR-PATHS][PASS] workflow trigger paths include required P1 gate inputs"
