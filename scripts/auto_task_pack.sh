#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CANDIDATES_JSON="${CANDIDATES_JSON:-$ROOT/run/auto-iterate/task-candidates.json}"
CHALLENGE_JSON="${CHALLENGE_JSON:-$ROOT/run/auto-iterate/task-challenges.json}"
BACKLOG_JSON="${BACKLOG_JSON:-$ROOT/run/auto-iterate/task-backlog.json}"
FAILURELOG_JSON="${FAILURELOG_JSON:-$ROOT/run/auto-iterate/task-failurelog.json}"
TASKS_FILE="${TASKS_FILE:-$ROOT/scripts/auto_iterate.tasks}"
MAX_APPEND="${MAX_APPEND:-4}"

/usr/bin/python3 "$ROOT/scripts/auto_task_discover.py" >/dev/null
/usr/bin/python3 "$ROOT/scripts/auto_task_challenge.py" >/dev/null
/usr/bin/python3 "$ROOT/scripts/auto_task_backlog.py" >/dev/null
/usr/bin/python3 "$ROOT/scripts/auto_task_failurelog.py" >/dev/null
/usr/bin/python3 "$ROOT/scripts/auto_task_prune_flaky.py" >/dev/null

if [[ ! -f "$CANDIDATES_JSON" ]]; then
  echo "missing candidates: $CANDIDATES_JSON"
  exit 2
fi

TMP="$(mktemp)"
/usr/bin/python3 - "$CANDIDATES_JSON" "$CHALLENGE_JSON" "$BACKLOG_JSON" "$FAILURELOG_JSON" "$TASKS_FILE" "$MAX_APPEND" > "$TMP" <<'PY'
import json, sys
from pathlib import Path

discover_path = Path(sys.argv[1])
challenge_path = Path(sys.argv[2])
backlog_path = Path(sys.argv[3])
failurelog_path = Path(sys.argv[4])
tasks_path = Path(sys.argv[5])
max_append = int(sys.argv[6])

discover = json.loads(discover_path.read_text()) if discover_path.exists() else {'candidates': []}
challenge = json.loads(challenge_path.read_text()) if challenge_path.exists() else {'candidates': []}
backlog = json.loads(backlog_path.read_text()) if backlog_path.exists() else {'candidates': []}
failurelog = json.loads(failurelog_path.read_text()) if failurelog_path.exists() else {'candidates': []}
text = tasks_path.read_text() if tasks_path.exists() else ''

pool = (
    list(failurelog.get('candidates', []))
    + list(backlog.get('candidates', []))
    + list(challenge.get('candidates', []))
    + list(discover.get('candidates', []))
)
added = []
for c in pool:
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
git commit -m "ops(auto-iterate): auto-fill task pool from failurelog+backlog+discover+challenge" || true

echo "[task-pack] appended task lines (failurelog+backlog+discover+challenge)"