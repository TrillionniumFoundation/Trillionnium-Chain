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

assert_contains_prefix() {
  local file="$1"
  local expected_prefix="$2"
  if ! grep -Fq "${expected_prefix}" "${file}"; then
    echo "missing expected line prefix: ${expected_prefix}" >&2
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

assert_json_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq "${unexpected}" "${file}"; then
    echo "unexpected json fragment present: ${unexpected}" >&2
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
assert_contains "${TMP_DIR}/status.out" "read_contract_source=rpc-read-surface"
assert_contains "${TMP_DIR}/status.out" "query_events_default_limit=100"
assert_contains "${TMP_DIR}/status.out" "query_events_max_limit=500"
assert_contains "${TMP_DIR}/status.out" "write_paths_exposed=false"
assert_contains "${TMP_DIR}/status.out" "historical_query_scope=rpc-retention-bounded"
assert_contains "${TMP_DIR}/status.out" "durability_boundary=ephemeral-rpc-window-only"
assert_contains "${TMP_DIR}/status.out" "archive_strategy=not-configured-static-scaffold"
assert_contains "${TMP_DIR}/status.out" "read_replica_strategy=not-configured-static-scaffold"
assert_contains "${TMP_DIR}/status.out" "deployment_topology=single-process-static-http-on-one-host"
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
assert_json_contains "${RUN_ROOT}/public/index.json" '"archive_strategy":"not-configured-static-scaffold"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"read_replica_strategy":"not-configured-static-scaffold"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"deployment_topology":"single-process-static-http-on-one-host"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"read_contract":{"mode":"read-only","source":"rpc-read-surface"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"day1_surface":["query-task/<task_id>","query-events/<task_id>?limit=<n>","query-capability-audit/<subject-or-token>","query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>"]'
assert_json_contains "${RUN_ROOT}/public/index.json" '"query_events_default_limit":100'
assert_json_contains "${RUN_ROOT}/public/index.json" '"query_events_max_limit":500'
assert_json_contains "${RUN_ROOT}/public/index.json" '"write_paths_exposed":false'
assert_json_not_contains "${RUN_ROOT}/public/index.json" 'block/<block_id>'
assert_json_not_contains "${RUN_ROOT}/public/index.json" 'tx/<tx_id>'
assert_json_not_contains "${RUN_ROOT}/public/index.json" 'account/<account_id>'
assert_json_contains "${RUN_ROOT}/public/index.json" '"local_health_url":"'"${HEALTH_URL}"'"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchor_archive_owner":"missing-placeholder-scaffold"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchor_lag_slo":"missing-placeholder-scaffold"'
assert_json_contains "${RUN_ROOT}/public/index.json" '"durable_read_anchors":{"ingestion_source":"missing-placeholder-scaffold","checkpoint_store":"missing-placeholder-scaffold","replay_start_anchor":"missing-placeholder-scaffold","retention_scope":"rpc-window-bounded","archive_owner":"missing-placeholder-scaffold","lag_slo":"missing-placeholder-scaffold"}'

CAPTURE_DIR="${TMP_DIR}/capture-helper"
EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${SCRIPT_DIR}/capture_explorer_scaffold_handoff.sh" --output-dir "${CAPTURE_DIR}" >"${TMP_DIR}/capture.out"

assert_contains "${TMP_DIR}/capture.out" "handoff_capture_output_dir=${CAPTURE_DIR}"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_status_path=${CAPTURE_DIR}/status.txt"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_index_path=${CAPTURE_DIR}/index.json"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_summary_path=${CAPTURE_DIR}/summary.txt"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_env_snapshot_path=${CAPTURE_DIR}/env.snapshot"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_template_path=trillionnium/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_durable_template_path=trillionnium/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_template_selection=placeholder-scaffold-only"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_durable_template_allowed=false"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_durable_template_rejection_reason=scaffold-capture-is-placeholder-only-and-missing-durable-read-anchors"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_state=running"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_health=ok"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_local_health=ok"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_scope=placeholder-only"
assert_contains "${TMP_DIR}/capture.out" "handoff_capture_blocker=still-open"
assert_contains "${CAPTURE_DIR}/status.txt" "state=running"
assert_contains "${CAPTURE_DIR}/status.txt" "health=ok"
assert_contains "${CAPTURE_DIR}/status.txt" "local_health=ok"
assert_contains "${CAPTURE_DIR}/status.txt" "deployment_evidence_scope=placeholder-only"
assert_contains "${CAPTURE_DIR}/status.txt" "rank1_read_surface_blocker=still-open"
assert_contains "${CAPTURE_DIR}/status.txt" "durable_indexer_status=not-implemented-in-this-scaffold"
assert_json_contains "${CAPTURE_DIR}/index.json" '"deployment_evidence_scope":"placeholder-only"'
assert_json_contains "${CAPTURE_DIR}/index.json" '"durable_indexer_status":"not-implemented-in-this-scaffold"'
assert_contains "${CAPTURE_DIR}/summary.txt" "service_mode=operator-facing-static-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "production_ready=false"
assert_contains "${CAPTURE_DIR}/summary.txt" "env_snapshot_path=${CAPTURE_DIR}/env.snapshot"
assert_contains "${CAPTURE_DIR}/summary.txt" "public_base_url=${PUBLIC_BASE_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "health_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "local_health_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "health_probe_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "health_probe_scope=operator-facing-health-url"
assert_contains "${CAPTURE_DIR}/summary.txt" "local_health_probe_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "local_health_probe_scope=local-bind-target"
assert_contains "${CAPTURE_DIR}/summary.txt" "health_probe_boundary_note=health_url_may_differ_from_local_health_url_and_must_not_be_collapsed_in_handoff"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_url=${PUBLIC_BASE_URL}/index.json"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_fetch_mode=curl"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_fetch_source=${PUBLIC_BASE_URL}/index.json"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_fetch_command=curl --silent --show-error --fail --max-time 5 ${PUBLIC_BASE_URL}/index.json"
assert_contains_prefix "${CAPTURE_DIR}/summary.txt" "index_json_fetched_at="
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_path_or_url=${PUBLIC_BASE_URL}/index.json"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_declares_day1_contract=true"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_declares_placeholder_only=true"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_service_mode=operator-facing-static-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_production_ready=false"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_rpc_base_url=${RPC_BASE_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_health_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_local_health_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_read_contract_mode=read-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_read_contract_source=rpc-read-surface"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_query_events_default_limit=100"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_query_events_max_limit=500"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_write_paths_exposed=false"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_historical_query_scope=rpc-retention-bounded"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durability_boundary=ephemeral-rpc-window-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_archive_strategy=not-configured-static-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_read_replica_strategy=not-configured-static-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_deployment_topology=single-process-static-http-on-one-host"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_deployment_evidence_scope=placeholder-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_rank1_read_surface_blocker=still-open"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_indexer_status=not-implemented-in-this-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_complete=false"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_missing_count=6"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_ingestion_source=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_checkpoint_store=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_retention_scope=rpc-window-bounded"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_archive_owner=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_durable_read_anchor_lag_slo=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_json_notes_include=static-scaffold-only,not-a-durable-indexer,not-a-production-read-model"
assert_contains "${CAPTURE_DIR}/summary.txt" "rpc_base_url=${RPC_BASE_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "read_contract_mode=read-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>"
assert_contains "${CAPTURE_DIR}/summary.txt" "historical_query_scope=rpc-retention-bounded"
assert_contains "${CAPTURE_DIR}/summary.txt" "durability_boundary=ephemeral-rpc-window-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "archive_strategy=not-configured-static-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "read_replica_strategy=not-configured-static-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "deployment_topology=single-process-static-http-on-one-host"
assert_contains "${CAPTURE_DIR}/summary.txt" "template_path=trillionnium/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_template_path=trillionnium/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "template_selection=placeholder-scaffold-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_template_allowed=false"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_template_rejection_reason=scaffold-capture-is-placeholder-only-and-missing-durable-read-anchors"
assert_contains "${CAPTURE_DIR}/summary.txt" "deployment_template_boundary=use-scaffold-template-until-non-placeholder-deployment-and-all-6-durable-read-anchors-exist"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_scaffold_handoff_template=trillionnium/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_scaffold_runbook=trillionnium/docs/runbooks/explorer-service-scaffold.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_durable_handoff_template=trillionnium/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_release_readiness=RELEASE_READINESS.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_day1_contract=trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_day1_contract_matrix=trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_go_no_go_panel=trillionnium/docs/release/TRNM_PUBLIC_MAINNET_GO_NO_GO_PANEL_2026-04-04.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_gap_matrix=trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_rank1_task_board=trillionnium/docs/release/TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "truth_source_blocker_board=trillionnium/docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md"
assert_contains "${CAPTURE_DIR}/summary.txt" "replay_command=./trillionnium/scripts/v2/explorer_service_up.sh"
assert_contains "${CAPTURE_DIR}/summary.txt" "status_command=./trillionnium/scripts/v2/explorer_service_status.sh"
assert_contains "${CAPTURE_DIR}/summary.txt" "rollback_command=./trillionnium/scripts/v2/explorer_service_down.sh"
assert_contains "${CAPTURE_DIR}/summary.txt" "deployment_evidence_scope=placeholder-only"
assert_contains "${CAPTURE_DIR}/summary.txt" "rank1_read_surface_blocker=still-open"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_indexer_status=not-implemented-in-this-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_complete=false"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_missing_count=6"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_ingestion_source=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_checkpoint_store=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_retention_scope=rpc-window-bounded"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_archive_owner=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/summary.txt" "durable_read_anchor_lag_slo=missing-placeholder-scaffold"
assert_contains "${CAPTURE_DIR}/env.snapshot" "EXPLORER_HOST=127.0.0.1"
assert_contains "${CAPTURE_DIR}/env.snapshot" "EXPLORER_PORT=${PORT}"
assert_contains "${CAPTURE_DIR}/env.snapshot" "EXPLORER_PUBLIC_BASE_URL=${PUBLIC_BASE_URL}"
assert_contains "${CAPTURE_DIR}/env.snapshot" "EXPLORER_HEALTH_URL=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/env.snapshot" "EXPLORER_RPC_BASE_URL=${RPC_BASE_URL}"

python3 - <<'PY' "${RUN_ROOT}/public/index.json"
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
data["deployment_evidence_scope"] = "durable-read-service"
path.write_text(json.dumps(data, separators=(",", ":")))
PY

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${SCRIPT_DIR}/capture_explorer_scaffold_handoff.sh" --output-dir "${TMP_DIR}/capture-should-fail" >"${TMP_DIR}/capture-drift.out" 2>&1 || true
assert_contains "${TMP_DIR}/capture-drift.out" 'refusing to capture handoff packet: fetched index.json drifted from placeholder scaffold contract ("deployment_evidence_scope":"placeholder-only")'

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
assert_contains "${TMP_DIR}/down.out" "read_contract_mode=read-only"
assert_contains "${TMP_DIR}/down.out" "read_contract_source=rpc-read-surface"
assert_contains "${TMP_DIR}/down.out" "query_events_default_limit=100"
assert_contains "${TMP_DIR}/down.out" "query_events_max_limit=500"
assert_contains "${TMP_DIR}/down.out" "write_paths_exposed=false"
assert_contains "${TMP_DIR}/down.out" "deployment_topology=single-process-static-http-on-one-host"
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

assert_contains "${ENV_FILE}" "EXPLORER_HOST=127.0.0.1"
assert_contains "${ENV_FILE}" "EXPLORER_PORT=${PORT}"
assert_contains "${ENV_FILE}" "EXPLORER_PUBLIC_BASE_URL=${PUBLIC_BASE_URL}"
assert_contains "${ENV_FILE}" "EXPLORER_HEALTH_URL=${HEALTH_URL}"
assert_contains "${ENV_FILE}" "EXPLORER_RPC_BASE_URL=${RPC_BASE_URL}"

cp "${ENV_FILE}" "${TMP_DIR}/env-before-preserve-check"
EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="https://override.should.not.persist.example" \
EXPLORER_HEALTH_URL="https://override.should.not.persist.example/healthz" \
EXPLORER_RPC_BASE_URL="https://override.should.not.persist.example/rpc" \
  "${UP_SCRIPT}" >"${TMP_DIR}/up-env-preserve.out"
assert_contains "${TMP_DIR}/up-env-preserve.out" "state=running"
assert_contains "${TMP_DIR}/up-env-preserve.out" "public_base_url=https://override.should.not.persist.example"
assert_contains "${TMP_DIR}/up-env-preserve.out" "health_url=https://override.should.not.persist.example/healthz"
assert_contains "${TMP_DIR}/up-env-preserve.out" "rpc_base_url=https://override.should.not.persist.example/rpc"
if ! cmp -s "${ENV_FILE}" "${TMP_DIR}/env-before-preserve-check"; then
  echo "existing env file was unexpectedly rewritten by already-running up path" >&2
  echo "--- before ---" >&2
  cat "${TMP_DIR}/env-before-preserve-check" >&2
  echo "--- after ---" >&2
  cat "${ENV_FILE}" >&2
  exit 1
fi

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="https://override.should.not.persist.example" \
EXPLORER_HEALTH_URL="https://override.should.not.persist.example/healthz" \
EXPLORER_RPC_BASE_URL="https://override.should.not.persist.example/rpc" \
  "${DOWN_SCRIPT}" >"${TMP_DIR}/down-env-preserve.out"
assert_contains "${TMP_DIR}/down-env-preserve.out" "state=down"

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

"${UP_SCRIPT}" >"${TMP_DIR}/up-invalid-config.out" 2>&1 || true
assert_contains "${TMP_DIR}/up-invalid-config.out" "refusing to start explorer service scaffold: EXPLORER_HEALTH_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/up-invalid-config.out" "state=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-config.out" "config_error=EXPLORER_HEALTH_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/up-invalid-config.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-config.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-config.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/up-invalid-config.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/up-invalid-config.out" "durable_indexer_status=not-implemented-in-this-scaffold"

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

cat >"${ENV_FILE}" <<EOF
EXPLORER_HOST=127.0.0.1
EXPLORER_PORT=${PORT}
EXPLORER_PUBLIC_BASE_URL=ftp://invalid-public-base-url
EXPLORER_HEALTH_URL=${HEALTH_URL}
EXPLORER_RPC_BASE_URL=${RPC_BASE_URL}
EOF

"${UP_SCRIPT}" >"${TMP_DIR}/up-invalid-public-base-url.out" 2>&1 || true
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "refusing to start explorer service scaffold: EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "state=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "config_error=EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/up-invalid-public-base-url.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${STATUS_SCRIPT}" >"${TMP_DIR}/status-invalid-public-base-url.out" || true
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "state=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "config_error=EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/status-invalid-public-base-url.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${DOWN_SCRIPT}" >"${TMP_DIR}/down-invalid-public-base-url.out"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "config_warning=EXPLORER_PUBLIC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "state=down"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "health=unknown"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "local_health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/down-invalid-public-base-url.out" "durable_indexer_status=not-implemented-in-this-scaffold"

cat >"${ENV_FILE}" <<EOF
EXPLORER_HOST=127.0.0.1
EXPLORER_PORT=${PORT}
EXPLORER_PUBLIC_BASE_URL=${PUBLIC_BASE_URL}
EXPLORER_HEALTH_URL=${HEALTH_URL}
EXPLORER_RPC_BASE_URL=ftp://invalid-rpc-base-url
EOF

"${UP_SCRIPT}" >"${TMP_DIR}/up-invalid-rpc-base-url.out" 2>&1 || true
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "refusing to start explorer service scaffold: EXPLORER_RPC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "state=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "config_error=EXPLORER_RPC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/up-invalid-rpc-base-url.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${STATUS_SCRIPT}" >"${TMP_DIR}/status-invalid-rpc-base-url.out" || true
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "state=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "config_error=EXPLORER_RPC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/status-invalid-rpc-base-url.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${DOWN_SCRIPT}" >"${TMP_DIR}/down-invalid-rpc-base-url.out"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "config_warning=EXPLORER_RPC_BASE_URL must start with http:// or https://"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "state=down"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "health=unknown"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "local_health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/down-invalid-rpc-base-url.out" "durable_indexer_status=not-implemented-in-this-scaffold"

cat >"${ENV_FILE}" <<EOF
EXPLORER_HOST=127.0.0.1
EXPLORER_PORT=0
EXPLORER_PUBLIC_BASE_URL=http://127.0.0.1:${PORT}
EXPLORER_HEALTH_URL=${HEALTH_URL}
EXPLORER_RPC_BASE_URL=${RPC_BASE_URL}
EOF

"${UP_SCRIPT}" >"${TMP_DIR}/up-invalid-port.out" 2>&1 || true
assert_contains "${TMP_DIR}/up-invalid-port.out" "refusing to start explorer service scaffold: EXPLORER_PORT must be an integer in [1, 65535]"
assert_contains "${TMP_DIR}/up-invalid-port.out" "state=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-port.out" "config_error=EXPLORER_PORT must be an integer in [1, 65535]"
assert_contains "${TMP_DIR}/up-invalid-port.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-port.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/up-invalid-port.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/up-invalid-port.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/up-invalid-port.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${STATUS_SCRIPT}" >"${TMP_DIR}/status-invalid-port.out" || true
assert_contains "${TMP_DIR}/status-invalid-port.out" "state=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-port.out" "config_error=EXPLORER_PORT must be an integer in [1, 65535]"
assert_contains "${TMP_DIR}/status-invalid-port.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-port.out" "local_health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-invalid-port.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/status-invalid-port.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/status-invalid-port.out" "durable_indexer_status=not-implemented-in-this-scaffold"

"${DOWN_SCRIPT}" >"${TMP_DIR}/down-invalid-port.out"
assert_contains "${TMP_DIR}/down-invalid-port.out" "config_warning=EXPLORER_PORT must be an integer in [1, 65535]"
assert_contains "${TMP_DIR}/down-invalid-port.out" "state=down"
assert_contains "${TMP_DIR}/down-invalid-port.out" "health=unknown"
assert_contains "${TMP_DIR}/down-invalid-port.out" "health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-port.out" "local_health_probe=not-run-state-down"
assert_contains "${TMP_DIR}/down-invalid-port.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/down-invalid-port.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/down-invalid-port.out" "durable_indexer_status=not-implemented-in-this-scaffold"

cat >"${ENV_FILE}" <<EOF
EXPLORER_HOST=127.0.0.1
EXPLORER_PORT=18081
EXPLORER_PUBLIC_BASE_URL=http://127.0.0.1:18081
EXPLORER_HEALTH_URL=http://127.0.0.1:18081/healthz
EXPLORER_RPC_BASE_URL=http://127.0.0.1:7777
EOF

EXPLORER_PORT=18082 \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status-explicit-port-override.out"
assert_contains "${TMP_DIR}/status-explicit-port-override.out" "state=down"
assert_contains "${TMP_DIR}/status-explicit-port-override.out" "bind_port=18082"
assert_contains "${TMP_DIR}/status-explicit-port-override.out" "public_base_url=http://127.0.0.1:18082"
assert_contains "${TMP_DIR}/status-explicit-port-override.out" "health_url=http://127.0.0.1:18082/healthz"
assert_contains "${TMP_DIR}/status-explicit-port-override.out" "local_health_url=http://127.0.0.1:18082/healthz"
assert_contains "${TMP_DIR}/status-explicit-port-override.out" "rpc_base_url=http://127.0.0.1:7777"

EXPLORER_PUBLIC_BASE_URL=https://explorer.override.example \
EXPLORER_HEALTH_URL=https://explorer.override.example/healthz \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status-explicit-url-override.out"
assert_contains "${TMP_DIR}/status-explicit-url-override.out" "state=down"
assert_contains "${TMP_DIR}/status-explicit-url-override.out" "bind_port=18081"
assert_contains "${TMP_DIR}/status-explicit-url-override.out" "public_base_url=https://explorer.override.example"
assert_contains "${TMP_DIR}/status-explicit-url-override.out" "health_url=https://explorer.override.example/healthz"
assert_contains "${TMP_DIR}/status-explicit-url-override.out" "local_health_url=http://127.0.0.1:18081/healthz"

EXPLORER_HOST=0.0.0.0 \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status-explicit-host-override.out"
assert_contains "${TMP_DIR}/status-explicit-host-override.out" "state=down"
assert_contains "${TMP_DIR}/status-explicit-host-override.out" "bind_host=0.0.0.0"
assert_contains "${TMP_DIR}/status-explicit-host-override.out" "bind_port=18081"
assert_contains "${TMP_DIR}/status-explicit-host-override.out" "public_base_url=http://0.0.0.0:18081"
assert_contains "${TMP_DIR}/status-explicit-host-override.out" "health_url=http://0.0.0.0:18081/healthz"
assert_contains "${TMP_DIR}/status-explicit-host-override.out" "local_health_url=http://127.0.0.1:18081/healthz"

EXPLORER_HOST=:: \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status-explicit-ipv6-host-override.out"
assert_contains "${TMP_DIR}/status-explicit-ipv6-host-override.out" "state=down"
assert_contains "${TMP_DIR}/status-explicit-ipv6-host-override.out" "bind_host=::"
assert_contains "${TMP_DIR}/status-explicit-ipv6-host-override.out" "bind_port=18081"
assert_contains "${TMP_DIR}/status-explicit-ipv6-host-override.out" "public_base_url=http://[::]:18081"
assert_contains "${TMP_DIR}/status-explicit-ipv6-host-override.out" "health_url=http://[::]:18081/healthz"
assert_contains "${TMP_DIR}/status-explicit-ipv6-host-override.out" "local_health_url=http://[::1]:18081/healthz"

EXPLORER_HOST='' \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status-empty-host-override.out" || true
assert_contains "${TMP_DIR}/status-empty-host-override.out" "state=invalid-config"
assert_contains "${TMP_DIR}/status-empty-host-override.out" "config_error=EXPLORER_HOST must not be empty"
assert_contains "${TMP_DIR}/status-empty-host-override.out" "bind_host="
assert_contains "${TMP_DIR}/status-empty-host-override.out" "health_probe=invalid-config"
assert_contains "${TMP_DIR}/status-empty-host-override.out" "local_health_probe=invalid-config"

EXPLORER_HOST='' \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${UP_SCRIPT}" >"${TMP_DIR}/up-empty-host-override.out" 2>&1 || true
assert_contains "${TMP_DIR}/up-empty-host-override.out" "refusing to start explorer service scaffold: EXPLORER_HOST must not be empty"
assert_contains "${TMP_DIR}/up-empty-host-override.out" "state=invalid-config"
assert_contains "${TMP_DIR}/up-empty-host-override.out" "config_error=EXPLORER_HOST must not be empty"

EXPLORER_HOST='' \
  "${DOWN_SCRIPT}" >"${TMP_DIR}/down-empty-host-override.out"
assert_contains "${TMP_DIR}/down-empty-host-override.out" "config_warning=EXPLORER_HOST must not be empty"
assert_contains "${TMP_DIR}/down-empty-host-override.out" "state=down"
assert_contains "${TMP_DIR}/down-empty-host-override.out" "bind_host="

CONFLICT_PORT=18083
python3 -m http.server "${CONFLICT_PORT}" --bind 127.0.0.1 >"${TMP_DIR}/listener-conflict.log" 2>&1 &
CONFLICT_PID=$!
trap 'kill "${CONFLICT_PID}" 2>/dev/null || true; cleanup' EXIT
sleep 1

EXPLORER_HOST=127.0.0.1 \
EXPLORER_PORT="${CONFLICT_PORT}" \
EXPLORER_PUBLIC_BASE_URL="http://127.0.0.1:${CONFLICT_PORT}" \
EXPLORER_HEALTH_URL="http://127.0.0.1:${CONFLICT_PORT}/healthz" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${UP_SCRIPT}" >"${TMP_DIR}/up-port-conflict.out" 2>&1 || true
assert_contains "${TMP_DIR}/up-port-conflict.out" "refusing to start explorer service scaffold: 127.0.0.1:${CONFLICT_PORT} already has a listener"
assert_contains "${TMP_DIR}/up-port-conflict.out" "state=down"
assert_contains "${TMP_DIR}/up-port-conflict.out" "health_probe=not-run-port-listener-conflict"
assert_contains "${TMP_DIR}/up-port-conflict.out" "local_health_probe=not-run-port-listener-conflict"
assert_contains "${TMP_DIR}/up-port-conflict.out" "deployment_evidence_scope=placeholder-only"
assert_contains "${TMP_DIR}/up-port-conflict.out" "rank1_read_surface_blocker=still-open"
assert_contains "${TMP_DIR}/up-port-conflict.out" "durable_indexer_status=not-implemented-in-this-scaffold"

kill "${CONFLICT_PID}" 2>/dev/null || true
wait "${CONFLICT_PID}" 2>/dev/null || true
trap cleanup EXIT


echo "explorer_service_contract_smoke=ok"
