#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/agent-user-phasea-gate.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'timeout-minutes: 45'
  'TZ: UTC'
  'LANG: C.UTF-8'
  'LC_ALL: C.UTF-8'
  'LC_NUMERIC: C'
  'LC_COLLATE: C'
  'LC_TIME: C'
  "PYTHONHASHSEED: '0'"
  "CI: 'true'"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic agent-user-phasea-gate guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] agent-user-phasea-gate keeps deterministic env + timeout guards"
