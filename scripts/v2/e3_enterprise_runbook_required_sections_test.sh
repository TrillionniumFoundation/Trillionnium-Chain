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

rollback_guard_phrases=(
  "撤销新增 capability token"
  "冻结本次接入环境凭据"
  "标记接入状态为 \`reverted\`"
  "根因标签"
  "--root-cause-tag"
  "trnm-onboard rollback"
  "rollback --org-id <org_id>"
  "--env <env>"
  "--change-ticket-id <change_ticket_id>"
  "--dry-run"
)

evidence_guard_phrases=(
  "协议版本与适配器传输层记录"
  "隐私分级策略快照（privacy_tier）"
  "最小任务 provenance_fingerprint 记录"
  "回滚命令与输出日志的 sha256 记录"
  "接入审批单（含 change_ticket_id）"
  "NTP 时钟偏差检查记录（≤300秒）"
)

for phrase in "${rollback_guard_phrases[@]}"; do
  if ! grep -Fq -- "$phrase" "$RUNBOOK"; then
    echo "[FAIL] rollback section missing guard phrase: $phrase" >&2
    exit 1
  fi
done

for phrase in "${evidence_guard_phrases[@]}"; do
  if ! grep -Fq -- "$phrase" "$RUNBOOK"; then
    echo "[FAIL] evidence checklist missing guard phrase: $phrase" >&2
    exit 1
  fi
done

echo "[PASS] E3 enterprise onboarding runbook includes required sections + rollback/evidence guard phrases"
