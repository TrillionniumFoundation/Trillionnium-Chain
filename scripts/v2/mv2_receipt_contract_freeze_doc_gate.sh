#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MV phase-B snapshot spec: $SPEC" >&2
  exit 1
fi

required_phrases=(
  "### MV-2：V2 回执接入前的契约冻结（Receipt Contract Freeze）"
  "fraud_proof | tee_receipt | zk_receipt"
  "task_id/proof_type/verdict/verified_at/cost_hint"
  "证明缺失/迟到/格式不合法"
  "不允许静默成功"
  "M2↔V2"
  "错误码与状态迁移表"
  "fail-closed"
)

for phrase in "${required_phrases[@]}"; do
  if ! grep -Fq -- "$phrase" "$SPEC"; then
    echo "[FAIL] missing MV2 receipt contract phrase: $phrase" >&2
    exit 1
  fi
done

echo "[PASS] MV2 receipt contract freeze doc guard phrases are present"
