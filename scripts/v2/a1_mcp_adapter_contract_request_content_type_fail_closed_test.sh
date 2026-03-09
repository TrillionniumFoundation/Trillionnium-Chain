#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="请求内容类型：\`Content-Type: application/json\`；非 JSON 请求按 \`400 schema_invalid\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter request Content-Type fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter request Content-Type fail-closed clause is present"
