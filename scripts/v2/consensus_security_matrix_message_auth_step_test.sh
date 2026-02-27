#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium-rust/scripts/run_consensus_security_matrix.sh"

if ! grep -Fq 'run_step "bft_message_auth" "./scripts/check_bft_message_auth.sh"' "$SCRIPT"; then
  echo "[FAIL] consensus security matrix missing bft_message_auth step" >&2
  exit 1
fi

echo "[PASS] consensus security matrix includes bft_message_auth step"
