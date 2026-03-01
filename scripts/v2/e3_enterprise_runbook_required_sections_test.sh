#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

required_headers=(
  "## 1. 目标与适用范围"
  "## 2. 前置条件（Preflight）"
  "## 3. 接入步骤（Step-by-step）"
  "## 4. 验收标准（DoD）"
  "## 5. 回滚方案"
  "## 6. 证据清单（Evidence Checklist）"
)

for header in "${required_headers[@]}"; do
  if ! grep -Fq "$header" "$RUNBOOK"; then
    echo "[FAIL] missing required header: $header" >&2
    exit 1
  fi
done

echo "[PASS] E3 enterprise onboarding runbook includes required sections"
