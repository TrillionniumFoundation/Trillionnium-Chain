#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

[[ -f "$WORKFLOW" ]] || { echo "[QUICK-GATE-PATHS][FAIL] missing workflow: $WORKFLOW" >&2; exit 1; }

check_trigger_path() {
  local trigger="$1"
  local path_glob="$2"
  python3 - "$WORKFLOW" "$trigger" "$path_glob" <<'PY'
import re
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
trigger = sys.argv[2]
needle = sys.argv[3]
anchor = f"  {trigger}:"
in_block = False
for line in lines:
    if not in_block:
        if line == anchor:
            in_block = True
        continue
    if re.match(r"^  [A-Za-z0-9_-]+:", line):
        break
    if line.strip() == f"- '{needle}'":
        sys.exit(0)
if any(line == anchor for line in lines):
    sys.exit(1)
sys.exit(2)
PY
}

for trigger in pull_request push; do
  if ! check_trigger_path "$trigger" "contracts-rust/**"; then
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      echo "[QUICK-GATE-PATHS][FAIL] missing workflow trigger block: $trigger" >&2
    else
      echo "[QUICK-GATE-PATHS][FAIL] missing workflow trigger path under $trigger: contracts-rust/**" >&2
    fi
    exit 1
  fi
done

echo "[QUICK-GATE-PATHS][PASS] quick-check workflow trigger paths include contracts-rust/** for pull_request + push"
