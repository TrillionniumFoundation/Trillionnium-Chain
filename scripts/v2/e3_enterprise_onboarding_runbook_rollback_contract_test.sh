#!/usr/bin/env bash
set -euo pipefail

# Pin UTF-8 locale so Chinese runbook assertions are deterministic across shells.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

require_line() {
  local needle="$1"
  if ! grep -Fq -- "$needle" "$RUNBOOK"; then
    echo "[FAIL] missing runbook contract line: $needle" >&2
    exit 1
  fi
}

require_line "## 5. 回滚方案"
require_line "--root-cause-tag"
require_line "--change-ticket-id"
require_line "--operator-id <operator_id>"
require_line "--dry-run"
require_line "--request-id <request_id>"
require_line "--expect-status reverted"
require_line "--expect-idempotent"
require_line "根因标签"
require_line 'ROLLBACK_LOG="$EVID_DIR/rollback-${request_id}.log"; REPLAY_LOG="$EVID_DIR/replay-${request_id}.log"'
require_line 'LC_ALL=C sha256sum "$ROLLBACK_LOG" "$REPLAY_LOG" > "$EVID_DIR/sha256-${request_id}.txt"'

echo "[PASS] E3 runbook keeps rollback/replay contract fields (root-cause-tag/change-ticket-id/operator-id/dry-run/request-id/expect-status/expect-idempotent) and deterministic request_id-anchored evidence log+hash templates"
