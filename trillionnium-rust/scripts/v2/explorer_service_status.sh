#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"
HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-http://${HOST}:${PORT}/healthz}"
PUBLIC_DIR="${RUN_ROOT}/public"
INDEX_URL="http://${HOST}:${PORT}/index.json"

state="down"
health="unknown"
pid_valid="true"

if [[ -f "${PID_FILE}" ]]; then
  pid="$(tr -d '[:space:]' <"${PID_FILE}")"
  if [[ -z "${pid}" || ! "${pid}" =~ ^[0-9]+$ ]]; then
    state="stale-pid"
    pid_valid="false"
  elif kill -0 "${pid}" 2>/dev/null; then
    state="running"
  else
    state="stale-pid"
  fi
else
  pid=""
fi

if command -v curl >/dev/null 2>&1; then
  if curl --silent --show-error --fail --max-time 2 "${HEALTH_URL}" >/dev/null 2>&1; then
    health="ok"
  else
    health="down"
  fi
fi

echo "state=${state}"
if [[ -n "${pid}" ]]; then
  echo "pid=${pid}"
fi
if [[ "${pid_valid}" != "true" ]]; then
  echo "pid_file_valid=false"
fi
echo "pid_file=${PID_FILE}"
echo "log_file=${LOG_FILE}"
echo "public_dir=${PUBLIC_DIR}"
echo "health_url=${HEALTH_URL}"
echo "index_url=${INDEX_URL}"
echo "health=${health}"
