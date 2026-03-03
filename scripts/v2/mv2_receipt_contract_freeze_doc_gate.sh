#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNAPSHOT_SPEC="$ROOT/docs/development/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md"
MASTER_SPEC="$ROOT/docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md"

if [[ ! -f "$SNAPSHOT_SPEC" ]]; then
  echo "[FAIL] missing MV phase-B snapshot spec: $SNAPSHOT_SPEC" >&2
  exit 1
fi

if [[ ! -f "$MASTER_SPEC" ]]; then
  echo "[FAIL] missing Web4 master spec: $MASTER_SPEC" >&2
  exit 1
fi

snapshot_required_phrases=(
  "### MV-2：V2 回执接入前的契约冻结（Receipt Contract Freeze）"
  "fraud_proof | tee_receipt | zk_receipt"
  "task_id/proof_type/verdict/verified_at/cost_hint"
  "证明缺失/迟到/格式不合法"
  "不允许静默成功"
  "M2↔V2"
  "错误码与状态迁移表"
  "ERR_M2V2_PROOF_MISSING"
  "ERR_M2V2_PROOF_LATE"
  "ERR_M2V2_PROOF_INVALID"
  "ERR_M2V2_SETTLEMENT_DEGRADED"
  "fail-closed"
)

master_required_phrases=(
  "### 10.3 Lane MV（2026-03-03）V2 回执契约冻结主文档锚点"
  "fraud_proof | tee_receipt | zk_receipt"
  "task_id/proof_type/verdict/verified_at/cost_hint"
  "证明缺失/迟到/格式不合法"
  "不允许静默成功"
  "M2↔V2"
  "错误码与状态迁移表"
  "ERR_M2V2_PROOF_MISSING"
  "ERR_M2V2_PROOF_LATE"
  "ERR_M2V2_PROOF_INVALID"
  "ERR_M2V2_SETTLEMENT_DEGRADED"
  "pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)"
  "fail-closed"
)

for phrase in "${snapshot_required_phrases[@]}"; do
  if ! grep -Fq -- "$phrase" "$SNAPSHOT_SPEC"; then
    echo "[FAIL] missing MV2 receipt contract phrase in snapshot: $phrase" >&2
    exit 1
  fi
done

for phrase in "${master_required_phrases[@]}"; do
  if ! grep -Fq -- "$phrase" "$MASTER_SPEC"; then
    echo "[FAIL] missing MV2 receipt contract phrase in master: $phrase" >&2
    exit 1
  fi
done

echo "[PASS] MV2 receipt contract freeze doc guard phrases are present (snapshot + master)"
