#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SNAPSHOT_SPEC="$ROOT/docs/archive/web4-history/WEB4_PHASE_B_MILESTONE_SNAPSHOT_2026-02-28.md"
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
  "pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)"
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

# Canonical contract lines must stay unique to avoid ambiguous spec anchors.
snapshot_field_contract_count=$(grep -Fc -- "task_id/proof_type/verdict/verified_at/cost_hint" "$SNAPSHOT_SPEC" || true)
master_field_contract_count=$(grep -Fc -- "task_id/proof_type/verdict/verified_at/cost_hint" "$MASTER_SPEC" || true)
if [[ "$snapshot_field_contract_count" -ne 1 || "$master_field_contract_count" -ne 1 ]]; then
  echo "[FAIL] expected exactly one unified MV2 field-contract phrase in snapshot and master" >&2
  echo "  snapshot_field_contract_count=$snapshot_field_contract_count master_field_contract_count=$master_field_contract_count" >&2
  exit 1
fi

snapshot_fail_closed_line_count=$(grep -Fc -- "不允许静默成功" "$SNAPSHOT_SPEC" || true)
master_fail_closed_line_count=$(grep -Fc -- "不允许静默成功" "$MASTER_SPEC" || true)
if [[ "$snapshot_fail_closed_line_count" -ne 1 || "$master_fail_closed_line_count" -ne 1 ]]; then
  echo "[FAIL] expected exactly one MV2 fail-closed phrase in snapshot and master" >&2
  echo "  snapshot_fail_closed_line_count=$snapshot_fail_closed_line_count master_fail_closed_line_count=$master_fail_closed_line_count" >&2
  exit 1
fi

snapshot_m2v2_boundary_count=$(grep -Fc -- "M2↔V2" "$SNAPSHOT_SPEC" || true)
master_m2v2_boundary_count=$(grep -Fc -- "M2↔V2" "$MASTER_SPEC" || true)
if [[ "$snapshot_m2v2_boundary_count" -ne 1 || "$master_m2v2_boundary_count" -ne 1 ]]; then
  echo "[FAIL] expected exactly one MV2 boundary phrase (M2↔V2) in snapshot and master" >&2
  echo "  snapshot_m2v2_boundary_count=$snapshot_m2v2_boundary_count master_m2v2_boundary_count=$master_m2v2_boundary_count" >&2
  exit 1
fi

snapshot_error_state_table_phrase_count=$(grep -Fc -- "错误码与状态迁移表" "$SNAPSHOT_SPEC" || true)
master_error_state_table_phrase_count=$(grep -Fc -- "错误码与状态迁移表" "$MASTER_SPEC" || true)
if [[ "$snapshot_error_state_table_phrase_count" -ne 1 || "$master_error_state_table_phrase_count" -ne 1 ]]; then
  echo "[FAIL] expected exactly one MV2 error/state-table phrase in snapshot and master" >&2
  echo "  snapshot_error_state_table_phrase_count=$snapshot_error_state_table_phrase_count master_error_state_table_phrase_count=$master_error_state_table_phrase_count" >&2
  exit 1
fi

for code in \
  "ERR_M2V2_PROOF_MISSING" \
  "ERR_M2V2_PROOF_LATE" \
  "ERR_M2V2_PROOF_INVALID" \
  "ERR_M2V2_SETTLEMENT_DEGRADED"
do
  snapshot_code_count=$(grep -Fc -- "$code" "$SNAPSHOT_SPEC" || true)
  master_code_count=$(grep -Fc -- "$code" "$MASTER_SPEC" || true)
  if [[ "$snapshot_code_count" -ne 1 || "$master_code_count" -ne 1 ]]; then
    echo "[FAIL] expected exactly one occurrence of $code in snapshot and master" >&2
    echo "  snapshot_code_count=$snapshot_code_count master_code_count=$master_code_count" >&2
    exit 1
  fi
done

snapshot_proof_union_anchor_count=$(grep -Fc -- '- 明确 `fraud_proof | tee_receipt | zk_receipt` 在市场结算视角的最小统一字段（`task_id/proof_type/verdict/verified_at/cost_hint`）。' "$SNAPSHOT_SPEC" || true)
master_proof_union_anchor_count=$(grep -Fc -- '- 锚点目标：把 `fraud_proof | tee_receipt | zk_receipt` 的统一回执字段固定到 Master，避免仅在专题文档生效。' "$MASTER_SPEC" || true)
if [[ "$snapshot_proof_union_anchor_count" -ne 1 || "$master_proof_union_anchor_count" -ne 1 ]]; then
  echo "[FAIL] expected exactly one MV2 proof union anchor line in snapshot and master" >&2
  echo "  snapshot_proof_union_anchor_count=$snapshot_proof_union_anchor_count master_proof_union_anchor_count=$master_proof_union_anchor_count" >&2
  exit 1
fi

snapshot_anchor_count=$(grep -Fc -- "### MV-2：V2 回执接入前的契约冻结（Receipt Contract Freeze）" "$SNAPSHOT_SPEC" || true)
master_anchor_count=$(grep -Fc -- "### 10.3 Lane MV（2026-03-03）V2 回执契约冻结主文档锚点" "$MASTER_SPEC" || true)
if [[ "$snapshot_anchor_count" -ne 1 || "$master_anchor_count" -ne 1 ]]; then
  echo "[FAIL] expected exactly one MV2 receipt contract anchor in snapshot and master" >&2
  echo "  snapshot_anchor_count=$snapshot_anchor_count master_anchor_count=$master_anchor_count" >&2
  exit 1
fi

expected_error_mapping_line='- 最小错误码映射（冻结）：`proof_missing -> ERR_M2V2_PROOF_MISSING`、`proof_late -> ERR_M2V2_PROOF_LATE`、`proof_invalid -> ERR_M2V2_PROOF_INVALID`、`settlement_degraded -> ERR_M2V2_SETTLEMENT_DEGRADED`。'
expected_state_mapping_line='- 最小状态迁移映射（冻结）：`pending_proof -> disputed(proof_missing|proof_late|proof_invalid) -> downgraded(settlement_degraded)`。'

mapfile -t snapshot_error_mapping_lines < <(grep -F -- "最小错误码映射（冻结）：" "$SNAPSHOT_SPEC" || true)
mapfile -t master_error_mapping_lines < <(grep -F -- "最小错误码映射（冻结）：" "$MASTER_SPEC" || true)
if [[ "${#snapshot_error_mapping_lines[@]}" -ne 1 || "${#master_error_mapping_lines[@]}" -ne 1 ]]; then
  echo "[FAIL] expected exactly one frozen MV2 error mapping line in snapshot and master" >&2
  echo "  snapshot_count=${#snapshot_error_mapping_lines[@]} master_count=${#master_error_mapping_lines[@]}" >&2
  exit 1
fi
snapshot_error_mapping_line="${snapshot_error_mapping_lines[0]}"
master_error_mapping_line="${master_error_mapping_lines[0]}"
if [[ "$snapshot_error_mapping_line" != "$master_error_mapping_line" ]]; then
  echo "[FAIL] MV2 frozen error mapping drift between snapshot and master" >&2
  echo "  snapshot: $snapshot_error_mapping_line" >&2
  echo "  master:   $master_error_mapping_line" >&2
  exit 1
fi
if [[ "$snapshot_error_mapping_line" != "$expected_error_mapping_line" ]]; then
  echo "[FAIL] MV2 frozen error mapping line drifted from canonical contract" >&2
  echo "  expected: $expected_error_mapping_line" >&2
  echo "  observed: $snapshot_error_mapping_line" >&2
  exit 1
fi

mapfile -t snapshot_state_mapping_lines < <(grep -F -- "最小状态迁移映射（冻结）：" "$SNAPSHOT_SPEC" || true)
mapfile -t master_state_mapping_lines < <(grep -F -- "最小状态迁移映射（冻结）：" "$MASTER_SPEC" || true)
if [[ "${#snapshot_state_mapping_lines[@]}" -ne 1 || "${#master_state_mapping_lines[@]}" -ne 1 ]]; then
  echo "[FAIL] expected exactly one frozen MV2 state mapping line in snapshot and master" >&2
  echo "  snapshot_count=${#snapshot_state_mapping_lines[@]} master_count=${#master_state_mapping_lines[@]}" >&2
  exit 1
fi
snapshot_state_mapping_line="${snapshot_state_mapping_lines[0]}"
master_state_mapping_line="${master_state_mapping_lines[0]}"
if [[ "$snapshot_state_mapping_line" != "$master_state_mapping_line" ]]; then
  echo "[FAIL] MV2 frozen state mapping drift between snapshot and master" >&2
  echo "  snapshot: $snapshot_state_mapping_line" >&2
  echo "  master:   $master_state_mapping_line" >&2
  exit 1
fi
if [[ "$snapshot_state_mapping_line" != "$expected_state_mapping_line" ]]; then
  echo "[FAIL] MV2 frozen state mapping line drifted from canonical contract" >&2
  echo "  expected: $expected_state_mapping_line" >&2
  echo "  observed: $snapshot_state_mapping_line" >&2
  exit 1
fi

echo "[PASS] MV2 receipt contract freeze doc guard phrases + snapshot/master mapping parity are present"
