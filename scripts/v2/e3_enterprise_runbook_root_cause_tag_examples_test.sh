#!/usr/bin/env bash
set -euo pipefail

# Pin UTF-8 locale so Chinese runbook assertions are deterministic across shells.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

required_line='根因标签建议使用稳定枚举（示例）：`schema_drift` / `auth_scope_mismatch` / `policy_conflict`。'
if ! grep -Fq -- "$required_line" "$RUNBOOK"; then
  echo "[FAIL] missing E3 root-cause-tag stable examples clause" >&2
  exit 1
fi

echo "[PASS] E3 runbook pins stable root-cause-tag examples for rollback evidence"
