#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="响应必须回显：X-TRNM-Request-ID（值必须等于请求 \`request_id\`，不一致按 \`502 upstream_execution_failed\` fail-closed）"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter exact request-id echo fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response request-id exact echo fail-closed clause is present"
