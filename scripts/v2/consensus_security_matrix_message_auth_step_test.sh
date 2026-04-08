#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/run_consensus_security_matrix.sh"

step='run_step "bft_message_auth" "./scripts/check_bft_message_auth.sh"'

count=$(grep -Fc "$step" "$SCRIPT" || true)
if [[ "$count" -eq 0 ]]; then
  echo "[FAIL] consensus security matrix missing bft_message_auth step" >&2
  exit 1
fi
if [[ "$count" -ne 1 ]]; then
  echo "[FAIL] consensus security matrix should contain exactly one bft_message_auth step (found $count)" >&2
  exit 1
fi

echo "[PASS] consensus security matrix includes exactly one bft_message_auth step"
