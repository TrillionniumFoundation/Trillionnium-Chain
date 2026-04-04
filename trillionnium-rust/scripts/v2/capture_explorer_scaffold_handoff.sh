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
INDEX_URL="$(status_field index_url)"
LOCAL_HEALTH_URL="$(status_field local_health_url)"
DEPLOYMENT_EVIDENCE_SCOPE="$(status_field deployment_evidence_scope)"
RANK1_BLOCKER="$(status_field rank1_read_surface_blocker)"
DURABLE_INDEXER_STATUS="$(status_field durable_indexer_status)"
DURABLE_READ_ANCHOR_COMPLETE="$(status_field durable_read_anchor_complete)"

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

if command -v curl >/dev/null 2>&1; then
  curl --silent --show-error --fail --max-time 5 "${INDEX_URL}" | tee "${INDEX_OUT}" >/dev/null
  INDEX_FETCH_MODE="curl"
  INDEX_FETCH_SOURCE="${INDEX_URL}"
else
  cp "${INDEX_FILE}" "${INDEX_OUT}"
  INDEX_FETCH_MODE="file-copy-fallback"
  INDEX_FETCH_SOURCE="${INDEX_FILE}"
fi

cat >"${SUMMARY_OUT}" <<EOF
captured_at_utc=${TIMESTAMP_UTC}
output_dir=${OUTPUT_DIR}
status_path=${STATUS_OUT}
index_path=${INDEX_OUT}
index_fetch_mode=${INDEX_FETCH_MODE}
index_fetch_source=${INDEX_FETCH_SOURCE}
local_health_url=${LOCAL_HEALTH_URL}
template_path=${TEMPLATE_PATH}
deployment_evidence_scope=${DEPLOYMENT_EVIDENCE_SCOPE}
rank1_read_surface_blocker=${RANK1_BLOCKER}
durable_indexer_status=${DURABLE_INDEXER_STATUS}
durable_read_anchor_complete=${DURABLE_READ_ANCHOR_COMPLETE}
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
