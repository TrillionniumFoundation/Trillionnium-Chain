#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ROOT="${RUST_ROOT}/run/explorer-service"
PID_FILE="${RUN_ROOT}/explorer-service.pid"

if [[ ! -f "${PID_FILE}" ]]; then
  echo "explorer service already stopped"
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
