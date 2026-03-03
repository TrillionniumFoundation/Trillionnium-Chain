#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# 发布级聚合 gate：关闭 Web4 高风险门禁盲区
# 可通过 WEB4_RELEASE_REQUIRED_GATES 覆盖（逗号分隔，相对 ROOT 路径）以做定向回归/失败注入。
DEFAULT_REQUIRED_GATES=(
  "scripts/v2/x2_settlement_contract_gate.sh"
  "scripts/v2/i2_token_lifecycle_gate.sh"
  "scripts/v2/d1_task_model_metadata_schema_gate.sh"
  "scripts/v2/a1_mcp_adapter_implementation_gate.sh"
  "scripts/v2/v1_proof_registry_contract_gate.sh"
  "scripts/v2/m2_policy_gate_nightly_signal_test.sh"
  "scripts/v2/mv2_receipt_contract_freeze_doc_gate.sh"
  "scripts/v2/e2_audit_report_generator_llm2_compact_schema_test.sh"
  "scripts/v2/e2_audit_report_generator_schema_token_spoof_test.sh"
  "scripts/v2/e2_audit_report_generator_reject_uppercase_schema_test.sh"
  "scripts/v2/e3_enterprise_runbook_required_sections_test.sh"
)

if [[ -n "${WEB4_RELEASE_REQUIRED_GATES:-}" ]]; then
  IFS=',' read -r -a REQUIRED_GATES <<<"${WEB4_RELEASE_REQUIRED_GATES}"
else
  REQUIRED_GATES=("${DEFAULT_REQUIRED_GATES[@]}")
fi

if [[ ${#REQUIRED_GATES[@]} -eq 0 ]]; then
  echo "[WEB4-RELEASE][FAIL] required gate list is empty" >&2
  exit 2
fi

RUN_DIR="${WEB4_RELEASE_RUN_DIR:-$ROOT/run/web4-release-gate/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

echo "[WEB4-RELEASE] start"
echo "[WEB4-RELEASE] root=$ROOT"
echo "[WEB4-RELEASE] run_dir=$RUN_DIR"

step() {
  local gate_rel="$1"
  local gate_abs="$ROOT/$gate_rel"
  local gate_name
  gate_name="$(basename "$gate_rel" .sh)"
  local log="$RUN_DIR/${gate_name}.log"

  if [[ ! -f "$gate_abs" ]]; then
    echo "[WEB4-RELEASE][FAIL] missing gate script: $gate_rel" >&2
    exit 2
  fi
  if [[ ! -x "$gate_abs" ]]; then
    echo "[WEB4-RELEASE][FAIL] gate script is not executable: $gate_rel" >&2
    exit 2
  fi

  echo "[WEB4-RELEASE][RUN] $gate_rel"
  "$gate_abs" 2>&1 | tee "$log"
  echo "[WEB4-RELEASE][PASS] $gate_rel"
}

for gate in "${REQUIRED_GATES[@]}"; do
  step "$gate"
done

echo "[WEB4-RELEASE][PASS] all required Web4 high-risk gates passed"
