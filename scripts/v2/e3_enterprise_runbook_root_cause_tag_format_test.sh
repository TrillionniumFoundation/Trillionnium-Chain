#!/usr/bin/env bash
set -euo pipefail

# Pin UTF-8 locale categories so Chinese runbook assertions are deterministic across shells.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export LC_CTYPE=C.UTF-8

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

required_line='根因标签格式约束：仅允许小写 snake_case 且必须字母开头（`[a-z][a-z0-9_]*`），禁止空格与大小写混用，避免审计聚合分桶漂移。'
if ! grep -Fq -- "$required_line" "$RUNBOOK"; then
  echo "[FAIL] missing E3 root-cause-tag format constraint clause" >&2
  exit 1
fi

echo "[PASS] E3 runbook pins root-cause-tag format constraint for deterministic audit aggregation"