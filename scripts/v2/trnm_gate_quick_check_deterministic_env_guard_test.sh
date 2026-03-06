#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'LC_COLLATE: C'
  'PYTHONHASHSEED: "0"'
  'CI: "true"'
  'timeout-minutes: 45'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic quick-check guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] trnm-gate-quick-check keeps deterministic env + timeout guards"
