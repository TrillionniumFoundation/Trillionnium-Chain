#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PUBLIC_DIR="${RUN_ROOT}/public"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"
HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
PUBLIC_BASE_URL="${EXPLORER_PUBLIC_BASE_URL:-http://${HOST}:${PORT}}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-${PUBLIC_BASE_URL}/healthz}"
INDEX_URL="${PUBLIC_BASE_URL}/index.json"
RPC_BASE_URL="${EXPLORER_RPC_BASE_URL:-http://127.0.0.1:7777}"
RPC_BASE_URL="${RPC_BASE_URL%/}"

emit_contract_fields() {
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
}

validate_runtime_contract() {
  if [[ -z "${HOST}" ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_HOST must not be empty"
    emit_contract_fields
    exit 1
  fi

  if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "refusing to start explorer service scaffold: EXPLORER_PORT must be an integer in [1, 65535]"
    emit_contract_fields
    exit 1
  fi

  if [[ -z "${PUBLIC_BASE_URL}" ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_PUBLIC_BASE_URL must not be empty"
    emit_contract_fields
    exit 1
  fi

  if [[ ! "${PUBLIC_BASE_URL}" =~ ^https?://.+ ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
    emit_contract_fields
    exit 1
  fi

  if [[ -z "${HEALTH_URL}" ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_HEALTH_URL must not be empty"
    emit_contract_fields
    exit 1
  fi

  if [[ ! "${HEALTH_URL}" =~ ^https?://.+ ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_HEALTH_URL must start with http:// or https://"
    emit_contract_fields
    exit 1
  fi

  if [[ -z "${RPC_BASE_URL}" ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_RPC_BASE_URL must not be empty"
    emit_contract_fields
    exit 1
  fi

  if [[ ! "${RPC_BASE_URL}" =~ ^https?://.+ ]]; then
    echo "refusing to start explorer service scaffold: EXPLORER_RPC_BASE_URL must start with http:// or https://"
    emit_contract_fields
    exit 1
  fi
}

mkdir -p "${PUBLIC_DIR}"

validate_runtime_contract

if ! command -v python3 >/dev/null 2>&1; then
  echo "refusing to start explorer service scaffold: python3 is required but not installed"
  emit_contract_fields
  exit 1
fi

if command -v lsof >/dev/null 2>&1 && lsof -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "refusing to start explorer service scaffold: ${HOST}:${PORT} already has a listener"
  emit_contract_fields
  exit 1
fi

if [[ -f "${PID_FILE}" ]]; then
  existing_pid="$(tr -d '[:space:]' <"${PID_FILE}")"
  if [[ "${existing_pid}" =~ ^[0-9]+$ ]] && kill -0 "${existing_pid}" 2>/dev/null; then
    echo "explorer service already running pid=${existing_pid}"
    emit_contract_fields
    exit 0
  fi
  rm -f "${PID_FILE}"
fi

cat >"${PUBLIC_DIR}/healthz" <<EOF
{"status":"ok","service":"explorer-service-scaffold","mode":"operator-facing","production_ready":false}
EOF

cat >"${PUBLIC_DIR}/index.json" <<EOF
{"service":"explorer-service-scaffold","health_url":"${HEALTH_URL}","rpc_base_url":"${RPC_BASE_URL}","read_contract":{"mode":"read-only","source":"rpc-read-surface","day1_surface":["query-task/<task_id>","query-events/<task_id>?limit=<n>","query-capability-audit/<subject-or-token>","query-normalized-audit-events/<task_id>?limit=<n>"],"query_events_default_limit":100,"query_events_max_limit":500,"write_paths_exposed":false},"notes":["static scaffold only","not a durable indexer","not a production read-model","historical queries remain bounded by RPC retention until a durable indexer/archive strategy exists"]}
EOF

cd "${PUBLIC_DIR}"
nohup python3 -m http.server "${PORT}" --bind "${HOST}" >"${LOG_FILE}" 2>&1 &
server_pid=$!
echo "${server_pid}" >"${PID_FILE}"
sleep 1

if ! kill -0 "${server_pid}" 2>/dev/null; then
  echo "explorer service scaffold failed to stay up"
  emit_contract_fields
  exit 1
fi

echo "started explorer service scaffold pid=${server_pid}"
emit_contract_fields
