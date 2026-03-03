#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="错误响应（4xx/5xx）也必须回显 \`X-TRNM-Request-ID\`，且必须与错误体 \`request_id\` 严格一致；不一致按 \`502 upstream_execution_failed\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter error response request-id parity fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter error response request-id parity fail-closed clause is present"
