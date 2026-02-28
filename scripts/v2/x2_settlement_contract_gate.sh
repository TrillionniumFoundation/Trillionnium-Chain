#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/x2-settlement-contract-gate/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

LOG="$RUN_DIR/x2_settlement_contract_gate.log"

echo "[X2][GATE] settlement contract gate started"
echo "[X2][GATE] artifacts=$RUN_DIR"

(
  cd "$ROOT/trillionnium-rust"
  cargo test -p trnm-bridge-poc --test x2_settlement_loop
) 2>&1 | tee "$LOG"

echo "[X2][GATE][PASS] settlement contract gate passed"
echo "[X2][GATE] log=$LOG"
