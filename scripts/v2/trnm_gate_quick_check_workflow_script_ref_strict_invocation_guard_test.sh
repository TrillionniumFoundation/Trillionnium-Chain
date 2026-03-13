#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'WORKFLOW_SCRIPT_REF_STRICT=1'
  'WORKFLOW_SCRIPT_REF_SUMMARY_PATH=run/quick-gate/workflow-script-refs-summary.json'
  './scripts/validate_workflow_script_refs.sh'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing workflow script-ref strict invocation guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] trnm-gate-quick-check keeps strict workflow script-ref validation invocation"
