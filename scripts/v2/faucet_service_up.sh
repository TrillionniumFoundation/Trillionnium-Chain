#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT/run/faucet-service.pid}"
LOG_FILE="${LOG_FILE:-$ROOT/run/faucet-service.log}"
HOST="${FAUCET_HOST:-127.0.0.1}"
PORT="${FAUCET_PORT:-8546}"
mkdir -p "$ROOT/run"
if [[ -f "$PID_FILE" ]] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
  echo "faucet_service.already_running pid=$(cat "$PID_FILE")"
  exit 0
fi
nohup bash -lc "cd '$ROOT' && FAUCET_HOST='$HOST' FAUCET_PORT='$PORT' python3 scripts/min_faucet_server.py" >"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "faucet_service.started pid=$(cat "$PID_FILE") host=$HOST port=$PORT"
echo "faucet_service.log=$LOG_FILE"
