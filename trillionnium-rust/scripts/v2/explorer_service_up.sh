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
HEALTH_URL="${EXPLORER_HEALTH_URL:-http://${HOST}:${PORT}/healthz}"
INDEX_URL="http://${HOST}:${PORT}/index.json"
INDEX_URL="http://${HOST}:${PORT}/index.json"

mkdir -p "${PUBLIC_DIR}"

if command -v lsof >/dev/null 2>&1 && lsof -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "refusing to start explorer service scaffold: ${HOST}:${PORT} already has a listener"
  echo "pid_file=${PID_FILE}"
  echo "log_file=${LOG_FILE}"
  echo "public_dir=${PUBLIC_DIR}"
  echo "health_url=${HEALTH_URL}"
  echo "index_url=${INDEX_URL}"
  exit 1
fi

if [[ -f "${PID_FILE}" ]]; then
  existing_pid="$(cat "${PID_FILE}")"
  if kill -0 "${existing_pid}" 2>/dev/null; then
    echo "explorer service already running pid=${existing_pid}"
    echo "pid_file=${PID_FILE}"
    echo "log_file=${LOG_FILE}"
    echo "public_dir=${PUBLIC_DIR}"
    echo "health_url=${HEALTH_URL}"
    echo "index_url=${INDEX_URL}"
    exit 0
  fi
  rm -f "${PID_FILE}"
fi

cat >"${PUBLIC_DIR}/healthz" <<EOF
{"status":"ok","service":"explorer-service-scaffold","mode":"operator-facing","production_ready":false}
EOF

cat >"${PUBLIC_DIR}/index.json" <<EOF
{"service":"explorer-service-scaffold","health_url":"${HEALTH_URL}","notes":["static scaffold only","not a durable indexer","not a production read-model"]}
EOF

cd "${PUBLIC_DIR}"
nohup python3 -m http.server "${PORT}" --bind "${HOST}" >"${LOG_FILE}" 2>&1 &
server_pid=$!
echo "${server_pid}" >"${PID_FILE}"
sleep 1

if ! kill -0 "${server_pid}" 2>/dev/null; then
  echo "explorer service scaffold failed to stay up"
  echo "pid_file=${PID_FILE}"
  echo "log_file=${LOG_FILE}"
  echo "public_dir=${PUBLIC_DIR}"
  echo "health_url=${HEALTH_URL}"
  echo "index_url=${INDEX_URL}"
  exit 1
fi

echo "started explorer service scaffold pid=${server_pid}"
echo "pid_file=${PID_FILE}"
echo "log_file=${LOG_FILE}"
echo "public_dir=${PUBLIC_DIR}"
echo "health_url=${HEALTH_URL}"
echo "index_url=${INDEX_URL}"
