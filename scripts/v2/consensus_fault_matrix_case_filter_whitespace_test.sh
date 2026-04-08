#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh"

needle='CASE_FILTER="$(printf '\''%s'\'' "$CASE_FILTER" | tr -d '\''[:space:]'\'')"'
if ! grep -Fq "$needle" "$SCRIPT"; then
  echo "[FAIL] consensus fault matrix missing CASE_FILTER whitespace canonicalization" >&2
  exit 1
fi

echo "[PASS] consensus fault matrix canonicalizes CASE_FILTER whitespace"
