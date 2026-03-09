#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="请求可接受类型：\`Accept\` 必须显式包含 \`application/json\`；缺失或不包含 JSON 按 \`400 schema_invalid\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter request Accept header fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter request Accept header fail-closed clause is present"
