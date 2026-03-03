#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="响应必须回显：X-TRNM-Schema-Version: mcp-adapter-v1；缺失或不匹配按 \`502 upstream_execution_failed\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response schema-version echo fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response schema-version echo fail-closed clause is present"
