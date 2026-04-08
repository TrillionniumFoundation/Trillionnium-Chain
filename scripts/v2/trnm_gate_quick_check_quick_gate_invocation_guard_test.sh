#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'QUICK_GATE_SUMMARY_PATH=run/quick-gate/summary.json'
  './scripts/quick_gate_shell.sh scripts trillionnium/scripts'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing quick-gate invocation guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] trnm-gate-quick-check keeps quick-gate dual-target invocation + summary path"
