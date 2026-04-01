#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"
PUBLIC_DIR="${RUN_ROOT}/public"
HEALTH_FILE="${PUBLIC_DIR}/healthz"
INDEX_FILE="${PUBLIC_DIR}/index.json"
HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
PUBLIC_BASE_URL="${EXPLORER_PUBLIC_BASE_URL:-http://${HOST}:${PORT}}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-${PUBLIC_BASE_URL}/healthz}"
INDEX_URL="${PUBLIC_BASE_URL}/index.json"
RPC_BASE_URL="${EXPLORER_RPC_BASE_URL:-http://127.0.0.1:7777}"
RPC_BASE_URL="${RPC_BASE_URL%/}"
LOCAL_HEALTH_URL="http://${HOST}:${PORT}/healthz"

emit_invalid_config() {
  local config_error="$1"
  echo "state=invalid-config"
  echo "config_error=${config_error}"
  echo "pid_file=${PID_FILE}"
  echo "log_file=${LOG_FILE}"
  echo "public_dir=${PUBLIC_DIR}"
  echo "health_file=${HEALTH_FILE}"
  echo "index_file=${INDEX_FILE}"
  echo "bind_host=${HOST}"
  echo "bind_port=${PORT}"
  echo "health_url=${HEALTH_URL}"
  echo "local_health_url=${LOCAL_HEALTH_URL}"
  echo "index_url=${INDEX_URL}"
  echo "rpc_base_url=${RPC_BASE_URL}"
  echo "service_mode=operator-facing-static-scaffold"
  echo "production_ready=false"
  echo "health=unknown"
  echo "health_probe=invalid-config"
  echo "health_probe_url=invalid-config"
}

validate_runtime_contract() {
  if [[ -z "${HOST}" ]]; then
    emit_invalid_config "EXPLORER_HOST must not be empty"
    exit 1
  fi

  if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    emit_invalid_config "EXPLORER_PORT must be an integer in [1, 65535]"
    exit 1
  fi

  if [[ -z "${PUBLIC_BASE_URL}" ]]; then
    emit_invalid_config "EXPLORER_PUBLIC_BASE_URL must not be empty"
    exit 1
  fi

  if [[ ! "${PUBLIC_BASE_URL}" =~ ^https?://.+ ]]; then
    emit_invalid_config "EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
    exit 1
  fi

  if [[ -z "${HEALTH_URL}" ]]; then
    emit_invalid_config "EXPLORER_HEALTH_URL must not be empty"
    exit 1
  fi

  if [[ ! "${HEALTH_URL}" =~ ^https?://.+ ]]; then
    emit_invalid_config "EXPLORER_HEALTH_URL must start with http:// or https://"
    exit 1
  fi

  if [[ -z "${RPC_BASE_URL}" ]]; then
    emit_invalid_config "EXPLORER_RPC_BASE_URL must not be empty"
    exit 1
  fi

  if [[ ! "${RPC_BASE_URL}" =~ ^https?://.+ ]]; then
    emit_invalid_config "EXPLORER_RPC_BASE_URL must start with http:// or https://"
    exit 1
  fi
}

state="down"
health="unknown"
health_probe="not-run-state-not-running"
health_probe_url="not-run-state-not-running"
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

if [[ "${state}" == "running" ]]; then
  if command -v curl >/dev/null 2>&1; then
    health_probe="active"
    health_probe_url="${HEALTH_URL}"
    if curl --silent --show-error --fail --max-time 2 "${HEALTH_URL}" >/dev/null 2>&1; then
      health="ok"
    else
      health="down"
    fi
  else
    health_probe="disabled-curl-unavailable"
    health_probe_url="curl-unavailable"
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
echo "health_file=${HEALTH_FILE}"
echo "index_file=${INDEX_FILE}"
echo "bind_host=${HOST}"
echo "bind_port=${PORT}"
echo "public_base_url=${PUBLIC_BASE_URL}"
echo "health_url=${HEALTH_URL}"
echo "local_health_url=${LOCAL_HEALTH_URL}"
echo "index_url=${INDEX_URL}"
echo "rpc_base_url=${RPC_BASE_URL}"
echo "service_mode=operator-facing-static-scaffold"
echo "production_ready=false"
echo "health=${health}"
echo "health_probe=${health_probe}"
echo "health_probe_url=${health_probe_url}"
