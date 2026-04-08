#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/run_consensus_security_matrix.sh"

required_steps=(
  'run_step "consensus_fault_matrix" "./scripts/run_consensus_fault_matrix.sh"'
  'run_step "bft_restart_recovery" "./scripts/check_bft_restart_recovery.sh"'
  'run_step "bft_message_auth" "./scripts/check_bft_message_auth.sh"'
)

for step in "${required_steps[@]}"; do
  if ! grep -Fq "$step" "$SCRIPT"; then
    echo "[FAIL] consensus security matrix missing hard-gate step: $step" >&2
    exit 1
  fi
done

echo "[PASS] consensus security matrix includes required hard-gate steps"
