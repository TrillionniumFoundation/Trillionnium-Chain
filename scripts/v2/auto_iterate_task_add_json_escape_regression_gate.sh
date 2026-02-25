#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

WF=".github/workflows/trnm-gate-quick-check.yml"
STEP_NAME="Quick gate summary JSON escape regression"
STEP_RUN="./scripts/v2/quick_gate_summary_json_escape_test.sh"

if [[ ! -f "$WF" ]]; then
  echo "workflow missing: $WF"
  exit 2
fi

if grep -Fq "$STEP_RUN" "$WF"; then
  echo "[task] workflow already contains: $STEP_RUN"
  exit 0
fi

/usr/bin/python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/trnm-gate-quick-check.yml')
s = p.read_text()
anchor = "      - name: PR7 TOP_N input guard regression\n"
insert = (
    "      - name: Quick gate summary JSON escape regression\n"
    "        run: |\n"
    "          ./scripts/v2/quick_gate_summary_json_escape_test.sh\n\n"
)
if anchor not in s:
    raise SystemExit('anchor step not found')
s = s.replace(anchor, insert + anchor, 1)
p.write_text(s)
PY

./scripts/v2/quick_gate_summary_json_escape_test.sh

git add "$WF"
git commit -m "ci(gate): add quick gate JSON-escape regression to quick-check"
echo "[task] committed workflow update"