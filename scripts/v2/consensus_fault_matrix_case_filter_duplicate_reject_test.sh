#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh"

needle='duplicate case'
if ! grep -Fq "$needle" "$SCRIPT"; then
  echo "[FAIL] consensus fault matrix missing duplicate CASE_FILTER rejection" >&2
  exit 1
fi

echo "[PASS] consensus fault matrix rejects duplicate CASE_FILTER entries"
