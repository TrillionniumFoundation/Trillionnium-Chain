#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

python3 - "$WF" <<'PY'
import sys
from pathlib import Path

wf = Path(sys.argv[1]).read_text()
needle = "- name: Verify runner-provisioned shellcheck\n        run: |\n          set -euo pipefail\n"
if needle not in wf:
    print("[FAIL] quick-check workflow must enable set -euo pipefail in the immutable shellcheck prerequisite step", file=sys.stderr)
    raise SystemExit(1)
print("[PASS] trnm-gate-quick-check keeps pipefail guard in the shellcheck prerequisite step")
PY
