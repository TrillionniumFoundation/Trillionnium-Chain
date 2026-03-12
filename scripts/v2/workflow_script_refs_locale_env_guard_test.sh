#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

required_lines=(
  'export TZ="${TZ:-UTC}"'
  'export LANG="${LANG:-C.UTF-8}"'
  'export LC_ALL="${LC_ALL:-C.UTF-8}"'
  'export LC_NUMERIC="${LC_NUMERIC:-C}"'
  'export LC_COLLATE="${LC_COLLATE:-C}"'
  'export LC_TIME="${LC_TIME:-C}"'
  'export LC_CTYPE="${LC_CTYPE:-C}"'
  'export LC_MESSAGES="${LC_MESSAGES:-C}"'
  'export LC_MONETARY="${LC_MONETARY:-C}"'
  'export LC_MEASUREMENT="${LC_MEASUREMENT:-C}"'
  'export LC_PAPER="${LC_PAPER:-C}"'
  'export LC_ADDRESS="${LC_ADDRESS:-C}"'
  'export LC_NAME="${LC_NAME:-C}"'
  'export LC_TELEPHONE="${LC_TELEPHONE:-C}"'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$SCRIPT"; then
    echo "[FAIL] validate_workflow_script_refs.sh missing deterministic locale export: $line" >&2
    exit 1
  fi
done

echo "[PASS] workflow script ref validator keeps deterministic locale exports aligned with CI shell gates"
