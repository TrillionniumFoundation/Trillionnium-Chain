#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PID_FILE="${PID_FILE:-$ROOT/run/explorer-service.pid}"
LOG_FILE="${LOG_FILE:-$ROOT/run/explorer-service.log}"
HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-http://$HOST:$PORT/healthz}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "explorer_service.status=down pid_file_missing path=$PID_FILE log_file=$LOG_FILE health_url=$HEALTH_URL"
  exit 0
fi

PID="$(cat "$PID_FILE")"
if [[ -z "$PID" ]]; then
  echo "explorer_service.status=down pid_file_empty path=$PID_FILE log_file=$LOG_FILE health_url=$HEALTH_URL"
  exit 0
fi

if ! ps -p "$PID" >/dev/null 2>&1; then
  echo "explorer_service.status=down stale_pid=$PID path=$PID_FILE log_file=$LOG_FILE health_url=$HEALTH_URL"
  exit 0
fi

if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
  echo "explorer_service.status=up pid=$PID path=$PID_FILE log_file=$LOG_FILE health_url=$HEALTH_URL"
else
  echo "explorer_service.status=degraded pid=$PID path=$PID_FILE log_file=$LOG_FILE health_url=$HEALTH_URL"
fi
