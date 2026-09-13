#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   auto_iterate_task_add_quickcheck_step.sh "Step Name" "./scripts/v2/test.sh" "commit message"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <step-name> <step-run> <commit-message>"
  exit 2
fi

if [[ "${TRNM_ALLOW_LEGACY_QUICKCHECK_MUTATION:-0}" != "1" ]]; then
  echo "legacy quick-check mutation is disabled; edit the explicit self-contained regression allowlist in the workflow instead" >&2
  exit 2
fi

STEP_NAME="$1"
STEP_RUN="$2"
COMMIT_MSG="$3"
WF=".github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "workflow missing: $WF"
  exit 2
fi

if ! [[ "$STEP_RUN" =~ ^\./scripts/v2/.+\.sh$ ]]; then
  echo "invalid step run path: $STEP_RUN"
  exit 2
fi

if [[ ! -x "${STEP_RUN#./}" ]]; then
  echo "step script missing or not executable: ${STEP_RUN#./}"
  exit 2
fi

if grep -Fq "$STEP_RUN" "$WF"; then
  echo "[task] workflow already contains: $STEP_RUN"
  exit 0
fi

/usr/bin/python3 - "$STEP_NAME" "$STEP_RUN" <<'PY'
import sys
from pathlib import Path

step_name = sys.argv[1]
step_run = sys.argv[2]
wf = Path('.github/workflows/trnm-gate-quick-check.yml')
s = wf.read_text()
anchor = "      - name: Upload quick gate summary\n"
insert = (
    f"      - name: {step_name}\n"
    f"        run: |\n"
    f"          {step_run}\n\n"
)
if anchor not in s:
    raise SystemExit('anchor step not found')
s = s.replace(anchor, insert + anchor, 1)
wf.write_text(s)
PY

bash -lc "$STEP_RUN"

git add "$WF"
git commit -m "$COMMIT_MSG"
echo "[task] committed workflow update: $STEP_RUN"
