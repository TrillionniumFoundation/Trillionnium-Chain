#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  '- name: Verify runner-provisioned shellcheck'
  'command -v shellcheck >/dev/null 2>&1'
  'shellcheck --version'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing immutable runner shellcheck prerequisite: $line" >&2
    exit 1
  fi
done

if grep -Eq 'sudo|apt-get|--with-deps' "$WF"; then
  echo "[FAIL] quick-check must not acquire host privileges or mutate runner packages" >&2
  exit 1
fi

echo "[PASS] trnm-gate-quick-check requires preprovisioned shellcheck without host mutation"
