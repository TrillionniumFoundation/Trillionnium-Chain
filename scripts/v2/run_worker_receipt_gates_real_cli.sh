#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

: "${TRNM_TX_CLI:=trnm-node}"

echo "[real-cli-gate] tx_cli=$TRNM_TX_CLI"
REQUIRE_REAL_TX_CLI=1 TRNM_TX_CLI="$TRNM_TX_CLI" ./scripts/v2/worker_real_cli_readiness.sh
TRNM_TX_CLI="$TRNM_TX_CLI" ./scripts/v2/run_worker_receipt_gates.sh

echo "[OK] worker receipt real-cli gates passed tx_cli=$TRNM_TX_CLI"
