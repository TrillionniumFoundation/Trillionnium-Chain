#!/usr/bin/env bash
set -euo pipefail

# Pin UTF-8 locale so Chinese runbook assertions are deterministic across shells.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
# Keep numeric/date formatting and timezone-stamped evidence checks stable across
# CI runners so grep/assertions never depend on host locale/timezone drift.
export LC_NUMERIC=C
export LC_TIME=C
export TZ=UTC

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/enterprise_onboarding_runbook_v1.md"

if [[ ! -f "$RUNBOOK" ]]; then
  echo "[FAIL] missing runbook: $RUNBOOK" >&2
  exit 1
fi

required_lines=(
  'NTP 时钟偏差检查记录（≤300秒）'
  '审计事件时间戳格式校验记录（RFC3339 UTC，后缀 `Z`）'
  '审计时间戳禁止小数秒（必须为整秒）'
  '审计事件序列时间戳单调不倒退校验记录（按事件顺序）'
  '时间戳格式示例（整秒、UTC）'
  '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$RUNBOOK"; then
    echo "[FAIL] missing deterministic timestamp evidence clause: $line" >&2
    exit 1
  fi
done

echo "[PASS] E3 runbook pins deterministic audit timestamp evidence constraints"
