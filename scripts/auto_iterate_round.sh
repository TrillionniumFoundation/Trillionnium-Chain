#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TASKS_FILE="${TASKS_FILE:-$ROOT/scripts/auto_iterate.tasks}"
STATE_DIR="${STATE_DIR:-$ROOT/run/auto-iterate}"
IDX_FILE="$STATE_DIR/next-task.idx"
LOG_FILE="${LOG_FILE:-$STATE_DIR/round.log}"

mkdir -p "$STATE_DIR"

if [[ ! -f "$TASKS_FILE" ]]; then
  echo "[round] tasks file not found: $TASKS_FILE" | tee -a "$LOG_FILE"
  exit 2
fi

TASKS=()
while IFS= read -r line; do
  [[ -z "${line// }" ]] && continue
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  TASKS+=("$line")
done < "$TASKS_FILE"

if [[ "${#TASKS[@]}" -eq 0 ]]; then
  echo "[round] no tasks configured" | tee -a "$LOG_FILE"
  exit 20
fi

idx=0
if [[ -f "$IDX_FILE" ]]; then
  idx="$(cat "$IDX_FILE")"
fi

if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
  idx=0
fi

pick=$(( idx % ${#TASKS[@]} ))
next=$(( (pick + 1) % ${#TASKS[@]} ))
printf "%s\n" "$next" > "$IDX_FILE"

task="${TASKS[$pick]}"
echo "[round] task[$pick]=${task}" | tee -a "$LOG_FILE"

before_head="$(git rev-parse HEAD)"

# Task should perform low-risk change + local validation + git commit.
bash -lc "$task" | tee -a "$LOG_FILE"

after_head="$(git rev-parse HEAD)"
if [[ "$before_head" == "$after_head" ]]; then
  echo "[round] no commit created by task" | tee -a "$LOG_FILE"
  exit 20
fi

echo "[round] commit created: $after_head" | tee -a "$LOG_FILE"
exit 0