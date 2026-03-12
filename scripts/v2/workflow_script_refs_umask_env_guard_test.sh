#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

required_lines=(
  'UMASK_VALUE="${UMASK:-022}"'
  'UMASK must be a 3- or 4-digit octal value'
  'umask "$UMASK_VALUE"'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$SCRIPT"; then
    echo "[FAIL] validate_workflow_script_refs.sh missing deterministic umask guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] workflow script ref validator keeps deterministic umask aligned with CI shell gates"
