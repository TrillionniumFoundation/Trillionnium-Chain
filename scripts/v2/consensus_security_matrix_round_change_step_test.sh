#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/run_consensus_security_matrix.sh"

step='run_step "bft_round_change" "./scripts/check_bft_round_change.sh"'

count=$(grep -Fc "$step" "$SCRIPT" || true)
if [[ "$count" -eq 0 ]]; then
  echo "[FAIL] consensus security matrix missing bft_round_change step" >&2
  exit 1
fi
if [[ "$count" -ne 1 ]]; then
  echo "[FAIL] consensus security matrix should contain exactly one bft_round_change step (found $count)" >&2
  exit 1
fi

echo "[PASS] consensus security matrix includes exactly one bft_round_change step"
