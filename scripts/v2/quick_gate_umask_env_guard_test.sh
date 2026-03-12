#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

required_lines=(
  'umask "${UMASK:-022}"'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$SCRIPT"; then
    echo "[FAIL] quick_gate_shell.sh missing deterministic umask guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] quick_gate_shell keeps deterministic umask aligned with CI shell gates"
