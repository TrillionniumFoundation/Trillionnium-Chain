#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_error_codes=(
  "400 schema_invalid"
  "401 capability_invalid"
  "403 policy_denied"
  "409 idempotency_conflict"
  "409 replay_detected"
  "502 upstream_execution_failed"
)

for code in "${required_error_codes[@]}"; do
  if ! grep -Fq "$code" "$SPEC"; then
    echo "[FAIL] missing MCP adapter error code contract: $code" >&2
    exit 1
  fi
done

if ! grep -Fq "错误响应最小字段" "$SPEC"; then
  echo "[FAIL] missing MCP adapter minimal error payload contract" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter error matrix contract is complete"
