#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT/run/explorer-service.pid}"
LOG_FILE="${LOG_FILE:-$ROOT/run/explorer-service.log}"
HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
mkdir -p "$ROOT/run"
if [[ -f "$PID_FILE" ]] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
  echo "explorer_service.already_running pid=$(cat "$PID_FILE")"
  exit 0
fi
nohup bash -lc "cd '$ROOT' && python3 scripts/min_explorer.py --host '$HOST' --port '$PORT'" >"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "explorer_service.started pid=$(cat "$PID_FILE") host=$HOST port=$PORT"
echo "explorer_service.log=$LOG_FILE"
