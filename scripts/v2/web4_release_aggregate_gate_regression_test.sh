#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/web4_release_aggregate_gate.sh"

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] aggregate gate must exist and be executable: $GATE" >&2
  exit 1
fi

required_refs=(
  "scripts/v2/x2_settlement_contract_gate.sh"
  "scripts/v2/i2_token_lifecycle_gate.sh"
  "scripts/v2/d1_task_model_metadata_schema_gate.sh"
  "scripts/v2/a1_mcp_adapter_implementation_gate.sh"
  "scripts/v2/v1_proof_registry_contract_gate.sh"
  "scripts/v2/m2_policy_gate_nightly_signal_test.sh"
  "scripts/v2/m2v2_error_state_contract_gate.sh"
  "scripts/v2/e2_audit_report_generator_llm2_compact_schema_test.sh"
  "scripts/v2/e2_audit_report_generator_schema_token_spoof_test.sh"
  "scripts/v2/e2_audit_report_generator_reject_uppercase_schema_test.sh"
  "scripts/v2/e3_enterprise_runbook_required_sections_test.sh"
)

for ref in "${required_refs[@]}"; do
  if ! grep -Fq "$ref" "$GATE"; then
    echo "[FAIL] aggregate gate missing required reference: $ref" >&2
    exit 1
  fi
done

forbidden_refs=(
  "scripts/v2/mv2_receipt_contract_freeze_doc_gate.sh"
  "scripts/v2/mv2_receipt_contract_freeze_doc_gate_regression_test.sh"
)

for ref in "${forbidden_refs[@]}"; do
  if grep -Fq "$ref" "$GATE"; then
    echo "[FAIL] aggregate gate must not depend on retired archived-document gate: $ref" >&2
    exit 1
  fi
done

NEG_LOG="$(mktemp -t web4-release-neg.XXXXXX.log)"
trap 'rm -f "$NEG_LOG"' EXIT

if WEB4_RELEASE_ALLOW_CI_OVERRIDE=1 \
  WEB4_RELEASE_REQUIRED_GATES="scripts/v2/definitely_missing_gate.sh" \
  "$GATE" >"$NEG_LOG" 2>&1; then
  echo "[FAIL] aggregate gate should fail when required gate script is missing" >&2
  exit 1
fi

if ! grep -Fq "missing gate script" "$NEG_LOG"; then
  echo "[FAIL] expected missing gate script error message in negative test" >&2
  cat "$NEG_LOG" >&2 || true
  exit 1
fi

echo "[PASS] web4_release_aggregate_gate_regression_test"
