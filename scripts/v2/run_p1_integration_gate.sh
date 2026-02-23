#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/p1-integration-gate/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

echo "[GATE] P1 integration gate started"
echo "[GATE] artifacts=$RUN_DIR"

step() {
  local name="$1"
  shift
  local log="$RUN_DIR/${name}.log"
  echo "[GATE][RUN] $name"
  "$@" 2>&1 | tee "$log"
  echo "[GATE][PASS] $name"
}

step sdk_js_quickstart_smoke bash -lc "cd '$ROOT/examples/sdk-js' && node --check quickstart.js && test -f README.md && test -f package.json"
step product_layer_smoke "$ROOT/scripts/v2/product_layer_smoke.sh"
step rpc_contract_v1_test bash -lc "cd '$ROOT/trillionnium-rust' && cargo test -p trnm-rpc --test rpc_contract_v1"

echo "[GATE][PASS] all checks passed"
