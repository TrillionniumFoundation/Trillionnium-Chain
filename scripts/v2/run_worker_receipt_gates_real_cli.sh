#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

: "${TRNM_TX_CLI:=trnm-cli}"

# normalize local relative script path to absolute to survive cwd switches in sub-scripts
if [[ "$TRNM_TX_CLI" == ./* || "$TRNM_TX_CLI" == scripts/* ]]; then
  TRNM_TX_CLI="$ROOT/${TRNM_TX_CLI#./}"
fi

echo "[real-cli-gate] tx_cli=$TRNM_TX_CLI"
REQUIRE_REAL_TX_CLI=1 TRNM_TX_CLI="$TRNM_TX_CLI" ./scripts/v2/worker_real_cli_readiness.sh
TRNM_WORKER_ALLOW_EXTERNAL_TX_CLI=1 \
  TRNM_TX_ADAPTER_MODE=command \
  TRNM_TX_CLI="$TRNM_TX_CLI" \
  ./scripts/v2/run_worker_receipt_gates.sh

echo "[OK] worker receipt real-cli gates passed tx_cli=$TRNM_TX_CLI"
