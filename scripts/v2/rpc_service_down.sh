#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT/run/rpc-service.pid}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "rpc_service.not_running"
  exit 0
fi

PID="$(cat "$PID_FILE")"
if ps -p "$PID" >/dev/null 2>&1; then
  kill "$PID" || true
  sleep 1
  if ps -p "$PID" >/dev/null 2>&1; then
    kill -9 "$PID" || true
  fi
  echo "rpc_service.stopped pid=$PID"
else
  echo "rpc_service.stale_pid pid=$PID"
fi

rm -f "$PID_FILE"
