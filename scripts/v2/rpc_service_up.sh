#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT/run/rpc-service.pid}"
LOG_FILE="${LOG_FILE:-$ROOT/run/rpc-service.log}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8545}"

mkdir -p "$ROOT/run"

if [[ -f "$PID_FILE" ]] && ps -p "$(cat "$PID_FILE")" >/dev/null 2>&1; then
  echo "rpc_service.already_running pid=$(cat "$PID_FILE")"
  exit 0
fi

nohup bash -lc "cd '$ROOT/trillionnium' && cargo run -q -p trnm-rpc -- serve --host '$HOST' --port '$PORT'" >"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "rpc_service.started pid=$(cat "$PID_FILE") host=$HOST port=$PORT"
echo "rpc_service.log=$LOG_FILE"
