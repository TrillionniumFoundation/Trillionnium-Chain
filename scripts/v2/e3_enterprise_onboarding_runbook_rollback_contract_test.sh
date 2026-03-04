#!/usr/bin/env bash
set -euo pipefail

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
require_line "--dry-run"
require_line "--request-id <request_id>"
require_line "根因标签"

echo "[PASS] E3 runbook keeps rollback contract fields (root-cause-tag/change-ticket-id/dry-run/request-id)"
