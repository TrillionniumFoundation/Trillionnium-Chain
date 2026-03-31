#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"
HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
PUBLIC_BASE_URL="${EXPLORER_PUBLIC_BASE_URL:-http://${HOST}:${PORT}}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-${PUBLIC_BASE_URL}/healthz}"
PUBLIC_DIR="${RUN_ROOT}/public"
INDEX_URL="${PUBLIC_BASE_URL}/index.json"
RPC_BASE_URL="${EXPLORER_RPC_BASE_URL:-http://127.0.0.1:7777}"
RPC_BASE_URL="${RPC_BASE_URL%/}"

validate_runtime_contract() {
  if [[ -z "${HOST}" ]]; then
    echo "state=invalid-config"
    echo "config_error=EXPLORER_HOST must not be empty"
    echo "pid_file=${PID_FILE}"
    echo "log_file=${LOG_FILE}"
    echo "public_dir=${PUBLIC_DIR}"
    echo "bind_host=${HOST}"
    echo "bind_port=${PORT}"
    echo "health_url=${HEALTH_URL}"
    echo "index_url=${INDEX_URL}"
    echo "rpc_base_url=${RPC_BASE_URL}"
    echo "service_mode=operator-facing-static-scaffold"
    echo "production_ready=false"
    echo "health=unknown"
    exit 1
  fi

  if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "state=invalid-config"
    echo "config_error=EXPLORER_PORT must be an integer in [1, 65535]"
    echo "pid_file=${PID_FILE}"
    echo "log_file=${LOG_FILE}"
    echo "public_dir=${PUBLIC_DIR}"
    echo "bind_host=${HOST}"
    echo "bind_port=${PORT}"
    echo "health_url=${HEALTH_URL}"
    echo "index_url=${INDEX_URL}"
    echo "rpc_base_url=${RPC_BASE_URL}"
    echo "service_mode=operator-facing-static-scaffold"
    echo "production_ready=false"
    echo "health=unknown"
    exit 1
  fi
}

state="down"
health="unknown"
pid_valid="true"

validate_runtime_contract

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
echo "bind_host=${HOST}"
echo "bind_port=${PORT}"
echo "health_url=${HEALTH_URL}"
echo "index_url=${INDEX_URL}"
echo "rpc_base_url=${RPC_BASE_URL}"
echo "service_mode=operator-facing-static-scaffold"
echo "production_ready=false"
echo "health=${health}"
