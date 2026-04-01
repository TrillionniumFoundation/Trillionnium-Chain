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

emit_contract_paths() {
  echo "pid_file=${PID_FILE}"
  echo "log_file=${LOG_FILE}"
  echo "public_dir=${PUBLIC_DIR}"
  echo "health_file=${HEALTH_FILE}"
  echo "index_file=${INDEX_FILE}"
  echo "bind_host=${HOST}"
  echo "bind_port=${PORT}"
  echo "health_url=${HEALTH_URL}"
  echo "index_url=${INDEX_URL}"
  echo "rpc_base_url=${RPC_BASE_URL}"
  echo "service_mode=operator-facing-static-scaffold"
  echo "production_ready=false"
}

validate_runtime_contract() {
  if [[ -z "${HOST}" ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_HOST must not be empty"
    emit_contract_paths
    exit 1
  fi

  if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "refusing to stop explorer service scaffold: EXPLORER_PORT must be an integer in [1, 65535]"
    emit_contract_paths
    exit 1
  fi

  if [[ -z "${PUBLIC_BASE_URL}" ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_PUBLIC_BASE_URL must not be empty"
    emit_contract_paths
    exit 1
  fi

  if [[ ! "${PUBLIC_BASE_URL}" =~ ^https?://.+ ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
    emit_contract_paths
    exit 1
  fi

  if [[ -z "${HEALTH_URL}" ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_HEALTH_URL must not be empty"
    emit_contract_paths
    exit 1
  fi

  if [[ ! "${HEALTH_URL}" =~ ^https?://.+ ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_HEALTH_URL must start with http:// or https://"
    emit_contract_paths
    exit 1
  fi

  if [[ -z "${RPC_BASE_URL}" ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_RPC_BASE_URL must not be empty"
    emit_contract_paths
    exit 1
  fi

  if [[ ! "${RPC_BASE_URL}" =~ ^https?://.+ ]]; then
    echo "refusing to stop explorer service scaffold: EXPLORER_RPC_BASE_URL must start with http:// or https://"
    emit_contract_paths
    exit 1
  fi
}

validate_runtime_contract

if [[ ! -f "${PID_FILE}" ]]; then
  echo "explorer service already stopped"
  emit_contract_paths
  exit 0
fi

pid="$(tr -d '[:space:]' <"${PID_FILE}")"
if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" 2>/dev/null; then
  kill "${pid}"
  wait_seconds=0
  while kill -0 "${pid}" 2>/dev/null; do
    if [[ "${wait_seconds}" -ge 5 ]]; then
      kill -9 "${pid}" 2>/dev/null || true
      break
    fi
    sleep 1
    wait_seconds=$((wait_seconds + 1))
  done
fi

rm -f "${PID_FILE}"
if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
  echo "stopped explorer service scaffold pid=${pid}"
else
  echo "cleared explorer service scaffold stale pid file"
fi
emit_contract_paths
