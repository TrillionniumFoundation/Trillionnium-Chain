#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"
ENV_FILE="${RUN_ROOT}/explorer-service.env"
PUBLIC_DIR="${RUN_ROOT}/public"
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
  echo "durable_read_anchor_complete=false"
  echo "durable_read_anchor_missing_count=6"
  echo "durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
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

emit_contract_paths() {
  local state="$1"
  local health="$2"
  local health_probe="$3"
  local local_health="$4"
  local local_health_probe="$5"
  local health_probe_url="$6"
  local local_health_probe_url="$7"

  echo "state=${state}"
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
  echo "health=${health}"
  echo "health_probe=${health_probe}"
  echo "health_probe_url=${health_probe_url}"
  echo "local_health=${local_health}"
  echo "local_health_probe=${local_health_probe}"
  echo "local_health_probe_url=${local_health_probe_url}"
}

runtime_contract_error() {
  if [[ -z "${HOST}" ]]; then
    echo "EXPLORER_HOST must not be empty"
    return 0
  fi

  if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "EXPLORER_PORT must be an integer in [1, 65535]"
    return 0
  fi

  if [[ -z "${PUBLIC_BASE_URL}" ]]; then
    echo "EXPLORER_PUBLIC_BASE_URL must not be empty"
    return 0
  fi

  if [[ ! "${PUBLIC_BASE_URL}" =~ ^https?://.+ ]]; then
    echo "EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
    return 0
  fi

  if [[ -z "${HEALTH_URL}" ]]; then
    echo "EXPLORER_HEALTH_URL must not be empty"
    return 0
  fi

  if [[ ! "${HEALTH_URL}" =~ ^https?://.+ ]]; then
    echo "EXPLORER_HEALTH_URL must start with http:// or https://"
    return 0
  fi

  if [[ -z "${RPC_BASE_URL}" ]]; then
    echo "EXPLORER_RPC_BASE_URL must not be empty"
    return 0
  fi

  if [[ ! "${RPC_BASE_URL}" =~ ^https?://.+ ]]; then
    echo "EXPLORER_RPC_BASE_URL must start with http:// or https://"
    return 0
  fi

  return 1
}

config_error=""
if config_error_candidate="$(runtime_contract_error)"; then
  config_error="${config_error_candidate}"
fi

if [[ ! -f "${PID_FILE}" ]]; then
  if [[ -n "${config_error}" ]]; then
    echo "explorer service already stopped (current env invalid: ${config_error})"
    echo "config_warning=${config_error}"
    echo "config_error=${config_error}"
  else
    echo "explorer service already stopped"
  fi
  emit_contract_paths "down" "unknown" "not-run-state-down" "unknown" "not-run-state-down" "not-run-state-down" "not-run-state-down"
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
if [[ -n "${config_error}" ]]; then
  echo "config_warning=${config_error}"
  echo "config_error=${config_error}"
fi
emit_contract_paths "down" "unknown" "not-run-state-down" "unknown" "not-run-state-down" "not-run-state-down" "not-run-state-down"
