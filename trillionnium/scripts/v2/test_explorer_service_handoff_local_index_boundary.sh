#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
UP_SCRIPT="${SCRIPT_DIR}/explorer_service_up.sh"
STATUS_SCRIPT="${SCRIPT_DIR}/explorer_service_status.sh"
DOWN_SCRIPT="${SCRIPT_DIR}/explorer_service_down.sh"
CAPTURE_SCRIPT="${SCRIPT_DIR}/capture_explorer_scaffold_handoff.sh"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"

TMP_DIR="$(mktemp -d)"
PORT="${EXPLORER_PORT:-18094}"
PUBLIC_BASE_URL="http://localhost:${PORT}"
HEALTH_URL="${PUBLIC_BASE_URL}/healthz"
LOCAL_HEALTH_URL="http://127.0.0.1:${PORT}/healthz"
PUBLIC_INDEX_URL="${PUBLIC_BASE_URL}/index.json"
LOCAL_INDEX_URL="http://127.0.0.1:${PORT}/index.json"
RPC_BASE_URL="http://127.0.0.1:7777"

cleanup() {
  EXPLORER_PORT="${PORT}" "${DOWN_SCRIPT}" >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

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

rm -rf "${RUN_ROOT}"
mkdir -p "${RUN_ROOT}"

EXPLORER_HOST=0.0.0.0 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${UP_SCRIPT}" >"${TMP_DIR}/up.out"

assert_contains "${TMP_DIR}/up.out" "public_base_url=${PUBLIC_BASE_URL}"
assert_contains "${TMP_DIR}/up.out" "health_url=${HEALTH_URL}"
assert_contains "${TMP_DIR}/up.out" "local_health_url=${LOCAL_HEALTH_URL}"

EXPLORER_HOST=0.0.0.0 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${STATUS_SCRIPT}" >"${TMP_DIR}/status.out"

assert_contains "${TMP_DIR}/status.out" "state=running"
assert_contains "${TMP_DIR}/status.out" "bind_host=0.0.0.0"
assert_contains "${TMP_DIR}/status.out" "public_base_url=${PUBLIC_BASE_URL}"
assert_contains "${TMP_DIR}/status.out" "health_url=${HEALTH_URL}"
assert_contains "${TMP_DIR}/status.out" "local_health_url=${LOCAL_HEALTH_URL}"
assert_contains "${TMP_DIR}/status.out" "index_url=${PUBLIC_INDEX_URL}"

curl --silent --show-error --fail --max-time 5 "${PUBLIC_INDEX_URL}" >"${TMP_DIR}/public-index.json"
curl --silent --show-error --fail --max-time 5 "${LOCAL_INDEX_URL}" >"${TMP_DIR}/local-index.json"

if ! cmp -s "${TMP_DIR}/public-index.json" "${TMP_DIR}/local-index.json"; then
  echo "public/local index fetch payloads differed unexpectedly" >&2
  echo "--- public ---" >&2
  cat "${TMP_DIR}/public-index.json" >&2
  echo "--- local ---" >&2
  cat "${TMP_DIR}/local-index.json" >&2
  exit 1
fi

CAPTURE_DIR="${TMP_DIR}/capture-helper"
EXPLORER_HOST=0.0.0.0 \
EXPLORER_PORT="${PORT}" \
EXPLORER_PUBLIC_BASE_URL="${PUBLIC_BASE_URL}" \
EXPLORER_HEALTH_URL="${HEALTH_URL}" \
EXPLORER_RPC_BASE_URL="${RPC_BASE_URL}" \
  "${CAPTURE_SCRIPT}" --output-dir "${CAPTURE_DIR}" >"${TMP_DIR}/capture.out"

assert_contains "${TMP_DIR}/capture.out" "handoff_capture_state=running"
assert_contains "${CAPTURE_DIR}/summary.txt" "health_url=${HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "local_health_url=${LOCAL_HEALTH_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_url=${PUBLIC_INDEX_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "local_index_url=${LOCAL_INDEX_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "health_probe_boundary_note=health_url_may_differ_from_local_health_url_and_must_not_be_collapsed_in_handoff"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_probe_boundary_note=index_url_may_differ_from_local_index_url_and_must_not_be_collapsed_in_handoff"
assert_contains "${CAPTURE_DIR}/summary.txt" "index_fetch_command=curl --silent --show-error --fail --max-time 5 ${PUBLIC_INDEX_URL}"
assert_contains "${CAPTURE_DIR}/summary.txt" "local_index_fetch_command=curl --silent --show-error --fail --max-time 5 ${LOCAL_INDEX_URL}"
