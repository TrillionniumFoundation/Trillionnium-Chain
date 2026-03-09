#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/a2a_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing A2A adapter contract spec: $SPEC" >&2
  exit 1
fi

required_error_lines=(
  "400 schema_invalid"
  "401 capability_invalid"
  "403 policy_denied"
  "404 task_not_found"
  "409 idempotency_conflict"
  "409 replay_detected"
  "502 upstream_execution_failed"
)

for phrase in "${required_error_lines[@]}"; do
  if ! grep -Fq -- "$phrase" "$SPEC"; then
    echo "[FAIL] missing fail-closed error mapping: $phrase" >&2
    exit 1
  fi
done

echo "[PASS] A2 A2A adapter contract keeps fail-closed HTTP/error-code mappings"
