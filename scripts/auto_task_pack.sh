#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CANDIDATES_JSON="${CANDIDATES_JSON:-$ROOT/run/auto-iterate/task-candidates.json}"
TASKS_FILE="${TASKS_FILE:-$ROOT/scripts/auto_iterate.tasks}"
MAX_APPEND="${MAX_APPEND:-4}"

/usr/bin/python3 "$ROOT/scripts/auto_task_discover.py" >/dev/null

if [[ ! -f "$CANDIDATES_JSON" ]]; then
  echo "missing candidates: $CANDIDATES_JSON"
  exit 2
fi

TMP="$(mktemp)"
/usr/bin/python3 - "$CANDIDATES_JSON" "$TASKS_FILE" "$MAX_APPEND" > "$TMP" <<'PY'
import json, sys
from pathlib import Path

cand_path = Path(sys.argv[1])
tasks_path = Path(sys.argv[2])
max_append = int(sys.argv[3])
obj = json.loads(cand_path.read_text())
text = tasks_path.read_text() if tasks_path.exists() else ''

added = []
for c in obj.get('candidates', []):
    line = f'bash ./scripts/v2/auto_iterate_task_add_quickcheck_step.sh "{c["step_name"]}" "{c["script"]}" "{c["commit_msg"]}"'
    if line in text:
        continue
    added.append(line)
    if len(added) >= max_append:
        break

for l in added:
    print(l)
PY

if [[ ! -s "$TMP" ]]; then
  echo "[task-pack] no new task lines"
  rm -f "$TMP"
  exit 20
fi

{
  echo
  echo "# Auto-filled by dual-subagent task pool"
  cat "$TMP"
} >> "$TASKS_FILE"
rm -f "$TMP"

git add "$TASKS_FILE"
git commit -m "ops(auto-iterate): auto-fill task pool from discovered low-risk regressions" || true

echo "[task-pack] appended task lines"