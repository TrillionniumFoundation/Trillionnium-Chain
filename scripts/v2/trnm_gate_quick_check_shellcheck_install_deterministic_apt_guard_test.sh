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

# Match standalone executable privilege/package-mutation tokens, not substrings
# in trusted actor names such as "Franksudoman".
privileged_pattern='(^|[^[:alnum:]_])(sudo|apt-get)([^[:alnum:]_]|$)|(^|[[:space:]])--with-deps([[:space:]]|$)'

if printf '%s\n' "github.actor == 'Franksudoman'" | grep -Eq "$privileged_pattern"; then
  echo "[FAIL] privilege guard matched a trusted actor-name substring" >&2
  exit 1
fi

if ! printf '%s\n' 'run: sudo apt-get install shellcheck' | grep -Eq "$privileged_pattern"; then
  echo "[FAIL] privilege guard no longer detects executable host mutation" >&2
  exit 1
fi

if grep -Eq "$privileged_pattern" "$WF"; then
  echo "[FAIL] quick-check must not acquire host privileges or mutate runner packages" >&2
  exit 1
fi

echo "[PASS] trnm-gate-quick-check requires preprovisioned shellcheck without host mutation"
