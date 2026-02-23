#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT/run/faucet-service.pid}"
if [[ ! -f "$PID_FILE" ]]; then
  echo "faucet_service.not_running"
  exit 0
fi
PID="$(cat "$PID_FILE")"
if ps -p "$PID" >/dev/null 2>&1; then
  kill "$PID" || true
  sleep 1
  ps -p "$PID" >/dev/null 2>&1 && kill -9 "$PID" || true
  echo "faucet_service.stopped pid=$PID"
else
  echo "faucet_service.stale_pid pid=$PID"
fi
rm -f "$PID_FILE"
