#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PUBLIC_DIR="${RUN_ROOT}/public"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"
ENV_FILE="${RUN_ROOT}/explorer-service.env"
HEALTH_FILE="${PUBLIC_DIR}/healthz"
INDEX_FILE="${PUBLIC_DIR}/index.json"

load_env_defaults() {
  local had_host="false"
  local had_port="false"
  local had_public_base_url="false"
  local had_health_url="false"
  local had_rpc_base_url="false"
  local host_value=""
  local port_value=""
  local public_base_url_value=""
  local health_url_value=""
  local rpc_base_url_value=""

  if [[ -n "${EXPLORER_HOST+x}" ]]; then
    had_host="true"
    host_value="${EXPLORER_HOST}"
  fi
  if [[ -n "${EXPLORER_PORT+x}" ]]; then
    had_port="true"
    port_value="${EXPLORER_PORT}"
  fi
  if [[ -n "${EXPLORER_PUBLIC_BASE_URL+x}" ]]; then
    had_public_base_url="true"
    public_base_url_value="${EXPLORER_PUBLIC_BASE_URL}"
  fi
  if [[ -n "${EXPLORER_HEALTH_URL+x}" ]]; then
    had_health_url="true"
    health_url_value="${EXPLORER_HEALTH_URL}"
  fi
  if [[ -n "${EXPLORER_RPC_BASE_URL+x}" ]]; then
    had_rpc_base_url="true"
    rpc_base_url_value="${EXPLORER_RPC_BASE_URL}"
  fi

  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a

  if [[ "${had_public_base_url}" != "true" ]] && [[ "${had_host}" == "true" || "${had_port}" == "true" ]]; then
    unset EXPLORER_PUBLIC_BASE_URL
  fi
  if [[ "${had_health_url}" != "true" ]] && [[ "${had_host}" == "true" || "${had_port}" == "true" || "${had_public_base_url}" == "true" ]]; then
    unset EXPLORER_HEALTH_URL
  fi

  if [[ "${had_host}" == "true" ]]; then
    EXPLORER_HOST="${host_value}"
  fi
  if [[ "${had_port}" == "true" ]]; then
    EXPLORER_PORT="${port_value}"
  fi
  if [[ "${had_public_base_url}" == "true" ]]; then
    EXPLORER_PUBLIC_BASE_URL="${public_base_url_value}"
  fi
  if [[ "${had_health_url}" == "true" ]]; then
    EXPLORER_HEALTH_URL="${health_url_value}"
  fi
  if [[ "${had_rpc_base_url}" == "true" ]]; then
    EXPLORER_RPC_BASE_URL="${rpc_base_url_value}"
  fi
}

if [[ -f "${ENV_FILE}" ]]; then
  load_env_defaults
fi

HOST="${EXPLORER_HOST:-127.0.0.1}"
PORT="${EXPLORER_PORT:-8090}"
URL_HOST="${HOST}"
if [[ "${URL_HOST}" == *:* && "${URL_HOST}" != \[*\] ]]; then
  URL_HOST="[${URL_HOST}]"
fi
PUBLIC_BASE_URL="${EXPLORER_PUBLIC_BASE_URL:-http://${URL_HOST}:${PORT}}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL%/}"
HEALTH_URL="${EXPLORER_HEALTH_URL:-${PUBLIC_BASE_URL}/healthz}"
INDEX_URL="${PUBLIC_BASE_URL}/index.json"
RPC_BASE_URL="${EXPLORER_RPC_BASE_URL:-http://127.0.0.1:7777}"
RPC_BASE_URL="${RPC_BASE_URL%/}"
LOCAL_PROBE_HOST="${HOST}"
case "${HOST}" in
  0.0.0.0)
    LOCAL_PROBE_HOST="127.0.0.1"
    ;;
  ::)
    LOCAL_PROBE_HOST="::1"
    ;;
esac
if [[ "${LOCAL_PROBE_HOST}" == *:* && "${LOCAL_PROBE_HOST}" != \[*\] ]]; then
  LOCAL_PROBE_HOST="[${LOCAL_PROBE_HOST}]"
fi
LOCAL_HEALTH_URL="http://${LOCAL_PROBE_HOST}:${PORT}/healthz"

emit_durable_read_anchor_fields() {
  echo "durable_read_anchor_ingestion_source=missing-placeholder-scaffold"
  echo "durable_read_anchor_checkpoint_store=missing-placeholder-scaffold"
  echo "durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold"
  echo "durable_read_anchor_retention_scope=rpc-window-bounded"
  echo "durable_read_anchor_archive_owner=missing-placeholder-scaffold"
  echo "durable_read_anchor_lag_slo=missing-placeholder-scaffold"
}

emit_read_contract_fields() {
  echo "read_contract_mode=read-only"
  echo "read_contract_source=rpc-read-surface"
  echo "day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>"
  echo "query_events_default_limit=100"
  echo "query_events_max_limit=500"
  echo "write_paths_exposed=false"
  echo "historical_query_scope=rpc-retention-bounded"
  echo "durability_boundary=ephemeral-rpc-window-only"
  echo "archive_strategy=not-configured-static-scaffold"
  echo "read_replica_strategy=not-configured-static-scaffold"
  echo "deployment_evidence_scope=placeholder-only"
  echo "rank1_read_surface_blocker=still-open"
  echo "durable_indexer_status=not-implemented-in-this-scaffold"
  emit_durable_read_anchor_fields
}

emit_contract_fields() {
  echo "pid_file=${PID_FILE}"
  echo "log_file=${LOG_FILE}"
  echo "env_file=${ENV_FILE}"
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
  emit_read_contract_fields
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

if [[ ! -f "${ENV_FILE}" ]]; then
  cat >"${ENV_FILE}" <<EOF
# Suggested operator-local explorer scaffold environment.
# Safe to edit for local/reverse-proxy deployment, but this scaffold remains static-only.
EXPLORER_HOST=${HOST}
EXPLORER_PORT=${PORT}
EXPLORER_PUBLIC_BASE_URL=${PUBLIC_BASE_URL}
EXPLORER_HEALTH_URL=${HEALTH_URL}
EXPLORER_RPC_BASE_URL=${RPC_BASE_URL}
EOF
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "refusing to start explorer service scaffold: python3 is required but not installed"
  emit_contract_fields
  exit 1
fi

port_has_listener() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"${PORT}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi

  python3 - <<'PY' "${HOST}" "${PORT}"
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
sock = socket.socket(family, socket.SOCK_STREAM)
try:
    sock.bind((host, port))
except OSError:
    sys.exit(0)
else:
    sys.exit(1)
finally:
    sock.close()
PY
}

if port_has_listener; then
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

health_ts_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

cat >"${HEALTH_FILE}" <<EOF
{"ok":true,"status":"ok","service":"explorer-service-scaffold","mode":"operator-facing","production_ready":false,"ts_unix_ms":${health_ts_unix_ms},"version":1}
EOF

cat >"${INDEX_FILE}" <<EOF
{"service":"explorer-service-scaffold","service_mode":"operator-facing-static-scaffold","production_ready":false,"health_url":"${HEALTH_URL}","local_health_url":"${LOCAL_HEALTH_URL}","rpc_base_url":"${RPC_BASE_URL}","deployment_evidence_scope":"placeholder-only","rank1_read_surface_blocker":"still-open","durable_indexer_status":"not-implemented-in-this-scaffold","read_contract":{"mode":"read-only","source":"rpc-read-surface","day1_surface":["query-task/<task_id>","query-events/<task_id>?limit=<n>","query-capability-audit/<subject-or-token>","query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>"],"query_events_default_limit":100,"query_events_max_limit":500,"write_paths_exposed":false,"historical_query_scope":"rpc-retention-bounded","durability_boundary":"ephemeral-rpc-window-only","archive_strategy":"not-configured-static-scaffold","read_replica_strategy":"not-configured-static-scaffold"},"durable_read_anchors":{"ingestion_source":"missing-placeholder-scaffold","checkpoint_store":"missing-placeholder-scaffold","replay_start_anchor":"missing-placeholder-scaffold","retention_scope":"rpc-window-bounded","archive_owner":"missing-placeholder-scaffold","lag_slo":"missing-placeholder-scaffold"},"notes":["static scaffold only","not a durable indexer","not a production read-model","historical queries remain bounded by RPC retention until a durable indexer/archive strategy exists","durable read anchors remain intentionally unset until a real indexer/read-model exists"]}
EOF

cd "${PUBLIC_DIR}"
nohup python3 -m http.server "${PORT}" --bind "${HOST}" >"${LOG_FILE}" 2>&1 &
server_pid=$!
echo "${server_pid}" >"${PID_FILE}"
sleep 1

if ! kill -0 "${server_pid}" 2>/dev/null; then
  rm -f "${PID_FILE}"
  echo "explorer service scaffold failed to stay up"
  emit_contract_fields
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  health_probe_ok="false"
  for _attempt in 1 2 3 4 5; do
    if curl --silent --show-error --fail --max-time 2 "${LOCAL_HEALTH_URL}" >/dev/null 2>&1; then
      health_probe_ok="true"
      break
    fi
    sleep 1
  done
  if [[ "${health_probe_ok}" != "true" ]]; then
    kill "${server_pid}" 2>/dev/null || true
    rm -f "${PID_FILE}"
    echo "explorer service scaffold failed local health probe url=${LOCAL_HEALTH_URL}"
    emit_contract_fields
    exit 1
  fi
fi

echo "started explorer service scaffold pid=${server_pid}"
emit_contract_fields
