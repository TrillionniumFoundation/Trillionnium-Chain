#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
STATUS_SCRIPT="${SCRIPT_DIR}/explorer_service_status.sh"
INDEX_FILE="${RUN_ROOT}/public/index.json"
TEMPLATE_PATH="trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md"

usage() {
  cat <<'EOF'
Usage: ./scripts/v2/capture_explorer_scaffold_handoff.sh [--output-dir <path>]

Captures one deterministic placeholder-only explorer scaffold handoff packet:
- status.txt (emitted contract fields)
- index.json (served/static Day-1 read contract markers)
- summary.txt (paths + template pointer + fail-closed scope)

The helper fails closed unless explorer_service_status.sh reports state=running,
health=ok, and local_health=ok.
EOF
}

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --output-dir" >&2
        usage >&2
        exit 1
      fi
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

TIMESTAMP_UTC="$(date -u +"%Y%m%dT%H%M%SZ")"
if [[ -z "${OUTPUT_DIR}" ]]; then
  OUTPUT_DIR="${RUN_ROOT}/handoff-${TIMESTAMP_UTC}"
fi
mkdir -p "${OUTPUT_DIR}"

STATUS_OUT="${OUTPUT_DIR}/status.txt"
INDEX_OUT="${OUTPUT_DIR}/index.json"
SUMMARY_OUT="${OUTPUT_DIR}/summary.txt"

"${STATUS_SCRIPT}" | tee "${STATUS_OUT}"

status_field() {
  local key="$1"
  awk -F= -v target="${key}" '$1 == target {print substr($0, index($0, "=") + 1); exit}' "${STATUS_OUT}"
}

STATE="$(status_field state)"
HEALTH="$(status_field health)"
LOCAL_HEALTH="$(status_field local_health)"
SERVICE_MODE="$(status_field service_mode)"
PRODUCTION_READY="$(status_field production_ready)"
BIND_HOST="$(status_field bind_host)"
BIND_PORT="$(status_field bind_port)"
PID_FILE_PATH="$(status_field pid_file)"
LOG_FILE_PATH="$(status_field log_file)"
ENV_FILE_PATH="$(status_field env_file)"
PUBLIC_DIR_PATH="$(status_field public_dir)"
HEALTH_FILE_PATH="$(status_field health_file)"
INDEX_FILE_PATH="$(status_field index_file)"
PUBLIC_BASE_URL="$(status_field public_base_url)"
HEALTH_URL="$(status_field health_url)"
INDEX_URL="$(status_field index_url)"
RPC_BASE_URL="$(status_field rpc_base_url)"
LOCAL_HEALTH_URL="$(status_field local_health_url)"
HEALTH_PROBE_URL="$(status_field health_probe_url)"
LOCAL_HEALTH_PROBE_URL="$(status_field local_health_probe_url)"
READ_CONTRACT_MODE="$(status_field read_contract_mode)"
READ_CONTRACT_SOURCE="$(status_field read_contract_source)"
DAY1_SURFACE="$(status_field day1_surface)"
QUERY_EVENTS_DEFAULT_LIMIT="$(status_field query_events_default_limit)"
QUERY_EVENTS_MAX_LIMIT="$(status_field query_events_max_limit)"
WRITE_PATHS_EXPOSED="$(status_field write_paths_exposed)"
HISTORICAL_QUERY_SCOPE="$(status_field historical_query_scope)"
DURABILITY_BOUNDARY="$(status_field durability_boundary)"
ARCHIVE_STRATEGY="$(status_field archive_strategy)"
READ_REPLICA_STRATEGY="$(status_field read_replica_strategy)"
DEPLOYMENT_EVIDENCE_SCOPE="$(status_field deployment_evidence_scope)"
RANK1_BLOCKER="$(status_field rank1_read_surface_blocker)"
DURABLE_INDEXER_STATUS="$(status_field durable_indexer_status)"
DURABLE_READ_ANCHOR_COMPLETE="$(status_field durable_read_anchor_complete)"
DURABLE_READ_ANCHOR_MISSING_COUNT="$(status_field durable_read_anchor_missing_count)"
DURABLE_READ_ANCHOR_MISSING_FIELDS="$(status_field durable_read_anchor_missing_fields)"
EXPECTED_DURABLE_READ_ANCHOR_MISSING_COUNT="6"
EXPECTED_DURABLE_READ_ANCHOR_MISSING_FIELDS="ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
DURABLE_READ_ANCHOR_INGESTION_SOURCE="$(status_field durable_read_anchor_ingestion_source)"
DURABLE_READ_ANCHOR_CHECKPOINT_STORE="$(status_field durable_read_anchor_checkpoint_store)"
DURABLE_READ_ANCHOR_REPLAY_START_ANCHOR="$(status_field durable_read_anchor_replay_start_anchor)"
DURABLE_READ_ANCHOR_RETENTION_SCOPE="$(status_field durable_read_anchor_retention_scope)"
DURABLE_READ_ANCHOR_ARCHIVE_OWNER="$(status_field durable_read_anchor_archive_owner)"
DURABLE_READ_ANCHOR_LAG_SLO="$(status_field durable_read_anchor_lag_slo)"
EXPECTED_DURABLE_READ_ANCHOR_INGESTION_SOURCE="missing-placeholder-scaffold"
EXPECTED_DURABLE_READ_ANCHOR_CHECKPOINT_STORE="missing-placeholder-scaffold"
EXPECTED_DURABLE_READ_ANCHOR_REPLAY_START_ANCHOR="missing-placeholder-scaffold"
EXPECTED_DURABLE_READ_ANCHOR_RETENTION_SCOPE="rpc-window-bounded"
EXPECTED_DURABLE_READ_ANCHOR_ARCHIVE_OWNER="missing-placeholder-scaffold"
EXPECTED_DURABLE_READ_ANCHOR_LAG_SLO="missing-placeholder-scaffold"

if [[ "${STATE}" != "running" ]]; then
  echo "refusing to capture handoff packet: explorer scaffold is not running (state=${STATE:-missing})" >&2
  exit 1
fi
if [[ "${HEALTH}" != "ok" ]]; then
  echo "refusing to capture handoff packet: public health probe is not ok (health=${HEALTH:-missing})" >&2
  exit 1
fi
if [[ "${LOCAL_HEALTH}" != "ok" ]]; then
  echo "refusing to capture handoff packet: local health probe is not ok (local_health=${LOCAL_HEALTH:-missing})" >&2
  exit 1
fi
if [[ "${DEPLOYMENT_EVIDENCE_SCOPE}" != "placeholder-only" ]]; then
  echo "refusing to capture handoff packet: deployment_evidence_scope must remain placeholder-only for this helper" >&2
  exit 1
fi
if [[ "${RANK1_BLOCKER}" != "still-open" ]]; then
  echo "refusing to capture handoff packet: rank1_read_surface_blocker must remain still-open for this helper" >&2
  exit 1
fi
if [[ "${DURABLE_INDEXER_STATUS}" != "not-implemented-in-this-scaffold" ]]; then
  echo "refusing to capture handoff packet: durable_indexer_status drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_COMPLETE}" != "false" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_complete must remain false for placeholder scaffold capture" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_MISSING_COUNT}" != "${EXPECTED_DURABLE_READ_ANCHOR_MISSING_COUNT}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_missing_count drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_MISSING_FIELDS}" != "${EXPECTED_DURABLE_READ_ANCHOR_MISSING_FIELDS}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_missing_fields drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_INGESTION_SOURCE}" != "${EXPECTED_DURABLE_READ_ANCHOR_INGESTION_SOURCE}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_ingestion_source drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_CHECKPOINT_STORE}" != "${EXPECTED_DURABLE_READ_ANCHOR_CHECKPOINT_STORE}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_checkpoint_store drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_REPLAY_START_ANCHOR}" != "${EXPECTED_DURABLE_READ_ANCHOR_REPLAY_START_ANCHOR}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_replay_start_anchor drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_RETENTION_SCOPE}" != "${EXPECTED_DURABLE_READ_ANCHOR_RETENTION_SCOPE}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_retention_scope drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_ARCHIVE_OWNER}" != "${EXPECTED_DURABLE_READ_ANCHOR_ARCHIVE_OWNER}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_archive_owner drifted from placeholder scaffold contract" >&2
  exit 1
fi
if [[ "${DURABLE_READ_ANCHOR_LAG_SLO}" != "${EXPECTED_DURABLE_READ_ANCHOR_LAG_SLO}" ]]; then
  echo "refusing to capture handoff packet: durable_read_anchor_lag_slo drifted from placeholder scaffold contract" >&2
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  curl --silent --show-error --fail --max-time 5 "${INDEX_URL}" | tee "${INDEX_OUT}" >/dev/null
  INDEX_FETCH_MODE="curl"
  INDEX_FETCH_SOURCE="${INDEX_URL}"
  INDEX_FETCH_COMMAND="curl --silent --show-error --fail --max-time 5 ${INDEX_URL}"
else
  cp "${INDEX_FILE}" "${INDEX_OUT}"
  INDEX_FETCH_MODE="file-copy-fallback"
  INDEX_FETCH_SOURCE="${INDEX_FILE}"
  INDEX_FETCH_COMMAND="cp ${INDEX_FILE} ${INDEX_OUT}"
fi

cat >"${SUMMARY_OUT}" <<EOF
captured_at_utc=${TIMESTAMP_UTC}
output_dir=${OUTPUT_DIR}
status_path=${STATUS_OUT}
index_path=${INDEX_OUT}
index_fetch_mode=${INDEX_FETCH_MODE}
index_fetch_source=${INDEX_FETCH_SOURCE}
index_fetch_command=${INDEX_FETCH_COMMAND}
service_mode=${SERVICE_MODE}
production_ready=${PRODUCTION_READY}
bind_host=${BIND_HOST}
bind_port=${BIND_PORT}
pid_file=${PID_FILE_PATH}
log_file=${LOG_FILE_PATH}
env_file=${ENV_FILE_PATH}
public_dir=${PUBLIC_DIR_PATH}
health_file=${HEALTH_FILE_PATH}
index_file=${INDEX_FILE_PATH}
public_base_url=${PUBLIC_BASE_URL}
health_url=${HEALTH_URL}
local_health_url=${LOCAL_HEALTH_URL}
health_probe_url=${HEALTH_PROBE_URL}
local_health_probe_url=${LOCAL_HEALTH_PROBE_URL}
index_url=${INDEX_URL}
rpc_base_url=${RPC_BASE_URL}
read_contract_mode=${READ_CONTRACT_MODE}
read_contract_source=${READ_CONTRACT_SOURCE}
day1_surface=${DAY1_SURFACE}
query_events_default_limit=${QUERY_EVENTS_DEFAULT_LIMIT}
query_events_max_limit=${QUERY_EVENTS_MAX_LIMIT}
write_paths_exposed=${WRITE_PATHS_EXPOSED}
historical_query_scope=${HISTORICAL_QUERY_SCOPE}
durability_boundary=${DURABILITY_BOUNDARY}
archive_strategy=${ARCHIVE_STRATEGY}
read_replica_strategy=${READ_REPLICA_STRATEGY}
template_path=${TEMPLATE_PATH}
replay_command=./trillionnium-rust/scripts/v2/explorer_service_up.sh
status_command=./trillionnium-rust/scripts/v2/explorer_service_status.sh
rollback_command=./trillionnium-rust/scripts/v2/explorer_service_down.sh
deployment_evidence_scope=${DEPLOYMENT_EVIDENCE_SCOPE}
rank1_read_surface_blocker=${RANK1_BLOCKER}
durable_indexer_status=${DURABLE_INDEXER_STATUS}
durable_read_anchor_complete=${DURABLE_READ_ANCHOR_COMPLETE}
durable_read_anchor_missing_count=${DURABLE_READ_ANCHOR_MISSING_COUNT}
durable_read_anchor_missing_fields=${DURABLE_READ_ANCHOR_MISSING_FIELDS}
durable_read_anchor_ingestion_source=${DURABLE_READ_ANCHOR_INGESTION_SOURCE}
durable_read_anchor_checkpoint_store=${DURABLE_READ_ANCHOR_CHECKPOINT_STORE}
durable_read_anchor_replay_start_anchor=${DURABLE_READ_ANCHOR_REPLAY_START_ANCHOR}
durable_read_anchor_retention_scope=${DURABLE_READ_ANCHOR_RETENTION_SCOPE}
durable_read_anchor_archive_owner=${DURABLE_READ_ANCHOR_ARCHIVE_OWNER}
durable_read_anchor_lag_slo=${DURABLE_READ_ANCHOR_LAG_SLO}
blocker_note=this_evidence_does_not_close_durable_indexer_historical_read_model_or_production_explorer_backend
EOF

echo "handoff_capture_output_dir=${OUTPUT_DIR}"
echo "handoff_capture_status_path=${STATUS_OUT}"
echo "handoff_capture_index_path=${INDEX_OUT}"
echo "handoff_capture_summary_path=${SUMMARY_OUT}"
echo "handoff_capture_template_path=${TEMPLATE_PATH}"
echo "handoff_capture_state=${STATE}"
echo "handoff_capture_health=${HEALTH}"
echo "handoff_capture_local_health=${LOCAL_HEALTH}"
echo "handoff_capture_scope=${DEPLOYMENT_EVIDENCE_SCOPE}"
echo "handoff_capture_blocker=${RANK1_BLOCKER}"
