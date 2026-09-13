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

assert_tx_terminal_from_log() {
  local log="$1"
  local status
  status="$(sed -n 's/^status=//p' "$log" | tail -n1 | tr '[:upper:]' '[:lower:]' | xargs)"

  if [[ -z "$status" ]]; then
    echo "[GATE][FAIL] cannot find tx status in log: $log"
    exit 1
  fi

  if [[ "$status" == "pending" ]]; then
    echo "[GATE][FAIL] tx final status must not be pending"
    exit 1
  fi

  if [[ "$status" != "committed" && "$status" != "fail" ]]; then
    echo "[GATE][FAIL] tx final status must be committed/fail, got='$status'"
    exit 1
  fi

  echo "[GATE][PASS] tx terminal status asserted: $status"
}

SDK_JS_QUICKSTART_CMD="${P1_GATE_SDK_JS_CMD:-cd '$ROOT/examples/sdk-js' && node --check quickstart.js && test -f README.md && test -f package.json}"
PRODUCT_LAYER_SMOKE_CMD="${P1_GATE_PRODUCT_LAYER_CMD:-$ROOT/scripts/v2/product_layer_smoke.sh}"
RPC_CONTRACT_V1_CMD="${P1_GATE_RPC_CONTRACT_CMD:-cd '$ROOT/trillionnium' && cargo test -p trnm-rpc --test rpc_contract_v1}"
X2_SETTLEMENT_GATE_CMD="${P1_GATE_X2_SETTLEMENT_CMD:-$ROOT/scripts/v2/x2_settlement_contract_gate.sh}"
I2_TOKEN_LIFECYCLE_GATE_CMD="${P1_GATE_I2_TOKEN_LIFECYCLE_CMD:-$ROOT/scripts/v2/i2_token_lifecycle_gate.sh}"
M2_POLICY_GATE_CMD="${P1_GATE_M2_POLICY_CMD:-cd '$ROOT/trillionnium' && cargo test -p trnm-rpc market_m2_policy_gate_guards_default_drift_to_min_boundaries}"
V1_PROOF_REGISTRY_GATE_CMD="${P1_GATE_V1_PROOF_REGISTRY_CMD:-$ROOT/scripts/v2/v1_proof_registry_contract_gate.sh}"
MV2_RECEIPT_CONTRACT_GATE_CMD="${P1_GATE_MV2_RECEIPT_CONTRACT_CMD:-$ROOT/scripts/v2/m2v2_error_state_contract_gate.sh}"
D2_INTEROP_GATE_CMD="${P1_GATE_D2_INTEROP_CMD:-cd '$ROOT/trillionnium' && cargo test -p trnm-types settlement_evidence_path_tracks_terminal_state_machine_outcome}"
SKIP_TX_ASSERT="${P1_GATE_SKIP_TX_ASSERT:-0}"

step sdk_js_quickstart_smoke bash -lc "$SDK_JS_QUICKSTART_CMD"
step product_layer_smoke bash -lc "$PRODUCT_LAYER_SMOKE_CMD"
if [[ "$SKIP_TX_ASSERT" != "1" ]]; then
  assert_tx_terminal_from_log "$RUN_DIR/product_layer_smoke.log"
fi
step rpc_contract_v1_test bash -lc "$RPC_CONTRACT_V1_CMD"
step x2_settlement_contract_gate bash -lc "$X2_SETTLEMENT_GATE_CMD"
step i2_token_lifecycle_gate bash -lc "$I2_TOKEN_LIFECYCLE_GATE_CMD"
step m2_policy_gate bash -lc "$M2_POLICY_GATE_CMD"
step v1_proof_registry_gate bash -lc "$V1_PROOF_REGISTRY_GATE_CMD"
step mv2_receipt_contract_gate bash -lc "$MV2_RECEIPT_CONTRACT_GATE_CMD"
step d2_interop_gate bash -lc "$D2_INTEROP_GATE_CMD"

echo "[GATE][PASS] all checks passed"
