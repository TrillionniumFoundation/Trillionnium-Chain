#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/web4-frontend-ci.yml"

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
  "PYTHONHASHSEED: '0'"
  "FORCE_COLOR: '0'"
  "NPM_CONFIG_UPDATE_NOTIFIER: 'false'"
  "CI: 'true'"
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic web4-frontend-ci guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] web4-frontend-ci keeps deterministic env + timeout guards"
