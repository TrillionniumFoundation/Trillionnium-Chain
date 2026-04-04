#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UP_SCRIPT="${SCRIPT_DIR}/explorer_service_up.sh"
STATUS_SCRIPT="${SCRIPT_DIR}/explorer_service_status.sh"
DOWN_SCRIPT="${SCRIPT_DIR}/explorer_service_down.sh"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
ENV_FILE="${RUN_ROOT}/explorer-service.env"
PID_FILE="${RUN_ROOT}/explorer-service.pid"
LOG_FILE="${RUN_ROOT}/explorer-service.log"

TMP_DIR="$(mktemp -d)"
cleanup() {
  EXPLORER_PORT="${EXPLORER_PORT:-18091}" "${DOWN_SCRIPT}" >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PORT="${EXPLORER_PORT:-18091}"
PUBLIC_BASE_URL="http://127.0.0.1:${PORT}"
HEALTH_URL="${PUBLIC_BASE_URL}/healthz"
RPC_BASE_URL="http://127.0.0.1:7777"

assert_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fqx "${expected}" "${file}"; then
    echo "missing expected line: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_json_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq "${expected}" "${file}"; then
    echo "missing expected json fragment: ${expected}" >&2
    echo "--- ${file} ---" >&2
    cat "${file}" >&2
    exit 1
  fi
}

rm -rf "${RUN_ROOT}"
mkdir -p "${RUN_ROOT}"

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${UP_SCRIPT}" >"${TMP_DIR}/up.out"

assert_contains "${TMP_DIR}/up.out" "service_mode=operator-facing-static-scaffold"
assert_contains "${TMP_DIR}/up.out" "production_ready=false"
assert_contains "${TMP_DIR}/up.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/up.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/up.out" "durable_indexer_status=not-implemented-in-this-scaffold"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_complete=false"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_missing_count=6"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_ingestion_source=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_checkpoint_store=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_retention_scope=rpc-window-bounded"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_archive_owner=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/up.out" "durable_read_anchor_lag_slo=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/up.out" "local_health_url=${HEALTH_URL}"
assert_contains "${TMP_DIR}/up.out" "rpc_base_url=${RPC_BASE_URL}"

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status.out"

assert_contains "${TMP_DIR}/status.out" "state=running"
assert_contains "${TMP_DIR}/status.out" "health=ok"
assert_contains "${TMP_DIR}/status.out" "local_health=ok"
assert_contains "${TMP_DIR}/status.out" "health_probe=active"
assert_contains "${TMP_DIR}/status.out" "local_health_probe=active"
assert_contains "${TMP_DIR}/status.out" "health_probe_url=${HEALTH_URL}"
assert_contains "${TMP_DIR}/status.out" "local_health_probe_url=${HEALTH_URL}"
assert_contains "${TMP_DIR}/status.out" "read_contract_mode=read-only"
assert_contains "${TMP_DIR}/status.out" "historical_query_scope=rpc-retention-bounded"
assert_contains "${TMP_DIR}/status.out" "durability_boundary=ephemeral-rpc-window-only"
assert_contains "${TMP_DIR}/status.out" "archive_strategy=not-configured-static-scaffold"
assert_contains "${TMP_DIR}/status.out" "read_replica_strategy=not-configured-static-scaffold"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_ingestion_source=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_checkpoint_store=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_retention_scope=rpc-window-bounded"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_archive_owner=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/status.out" "durable_read_anchor_lag_slo=missing-placeholder-scaffold"

assert_json_contains "${RUN_ROOT}/public/index.json" '"service_mode":"operator-facing-static-scaffold"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"production_ready":false'
assert_json_contains "${RUN_ROOT}/public/index.json" '"deployment_evidence_scope":"placeholder-only"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"rank1_read_surface_blocker":"still-open"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_indexer_status":"not-implemented-in-this-scaffold"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchor_complete":false'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchor_missing_count":6'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchor_missing_fields":"ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"historical_query_scope":"rpc-retention-bounded"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durability_boundary":"ephemeral-rpc-window-only"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchors":{"ingestion_source":"missing-placeholder-scaffold","checkpoint_store":"missing-placeholder-scaffold","replay_start_anchor":"missing-placeholder-scaffold","retention_scope":"rpc-window-bounded","archive_owner":"missing-placeholder-scaffold","lag_slo":"missing-placeholder-scaffold"}'

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${DOWN_SCRIPT}" >"${TMP_DIR}/down.out"

assert_contains "${TMP_DIR}/down.out" "state=down"
assert_contains "${TMP_DIR}/down.out" "health=unknown"
assert_contains "${TMP_DIR}/down.out" "local_health=unknown"
assert_contains "${TMP_DIR}/down.out" "health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down.out" "local_health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down.out" "health_probe_url=not-run-state-down"
assert_contains "${TMP_DIR}/down.out" "local_health_probe_url=not-run-state-down"
assert_contains "${TMP_DIR}/down.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/down.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/down.out" "durable_indexer_status=not-implemented-in-this-scaffold"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_ingestion_source=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_checkpoint_store=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_retention_scope=rpc-window-bounded"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_archive_owner=missing-placeholder-scaffold"
assert_contains "${TMP_DIR}/down.out" "durable_read_anchor_lag_slo=missing-placeholder-scaffold"

if [[ -f "${PID_FILE}" ]]; then
  echo "pid file still present after shutdown: ${PID_FILE}" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "expected env file to be created: ${ENV_FILE}" >&2
  exit 1
fi

if [[ ! -f "${LOG_FILE}" ]]; then
  echo "expected log file to exist: ${LOG_FILE}" >&2
  exit 1
fi

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${UP_SCRIPT}" >"${TMP_DIR}/up-invalid-env.out"

cat >"${ENV_FILE}" <<EOF
EXPLORER_HOST=127.0.0.1
EXPLORER_PORT=${PORT}
EXPLORER_PUBLIC_BASE_URL=${PUBLIC_BASE_URL}
EXPLORER_HEALTH_URL=ftp://invalid-health-url
EXPLORER_RPC_BASE_URL=${RPC_BASE_URL}
EOF

"${STATUS_SCRIPT}" >"${TMP_DIR}/status-invalid-env.out" || true
assert_contains "${TMP_DIR}/status-invalid-env.out" "state=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-env.out" "config_error=EXPLORER_HEALTH_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/status-invalid-env.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-env.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-env.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/status-invalid-env.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/status-invalid-env.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${DOWN_SCRIPT}" >"${TMP_DIR}/down-invalid-env.out"
assert_contains "${TMP_DIR}/down-invalid-env.out" "config_warning=EXPLORER_HEALTH_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/down-invalid-env.out" "state=down"
assert_contains "${TMP_DIR}/down-invalid-env.out" "health=unknown"
assert_contains "${TMP_DIR}/down-invalid-env.out" "health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-env.out" "local_health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-env.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/down-invalid-env.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/down-invalid-env.out" "durable_indexer_status=not-implemented-in-this-scaffold"

if [[ -f "${PID_FILE}" ]]; then
  echo "pid file still present after invalid-env shutdown: ${PID_FILE}" >&2
  exit 1
fi

echo "explorer_service_contract_smoke=ok"
