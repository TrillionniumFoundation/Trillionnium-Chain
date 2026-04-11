#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUNBOOK_PATH="${ROOT_DIR}/docs/runbooks/mainnet-observability-alerting-starter-pack.md"

[[ -f "${RUNBOOK_PATH}" ]] || {
  echo "missing runbook: ${RUNBOOK_PATH}" >&2
  exit 1
}

assert_contains_once() {
  local needle="$1"
  local count
  count=$(grep -Fxc -- "$needle" "${RUNBOOK_PATH}" || true)
  if [[ "$count" -ne 1 ]]; then
    echo "expected exactly one line match for: $needle (got $count)" >&2
    exit 1
  fi
}

assert_contains() {
  local needle="$1"
  grep -Fq -- "$needle" "${RUNBOOK_PATH}" || {
    echo "missing required text: $needle" >&2
    exit 1
  }
}

assert_contains '### Stable first-stop panel names'
assert_contains_once '- `Node liveness / height progress`'
assert_contains_once '- `Consensus instability / rollback pressure`'
assert_contains_once '- `RPC health / read surface`'
assert_contains_once '- `Worker execution / receipt flow`'
assert_contains_once '- `Evidence / replay integrity`'
assert_contains_once '- `Oracle-specific drill-down`'
assert_contains_once '- `Bridge relay / settlement integrity`'
assert_contains '- `first_stop_panel`: `<Node liveness / height progress|Consensus instability / rollback pressure|RPC health / read surface|Worker execution / receipt flow|Evidence / replay integrity|Oracle-specific drill-down|Bridge relay / settlement integrity|unknown>`'
