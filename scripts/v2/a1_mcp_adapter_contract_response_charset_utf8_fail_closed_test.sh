#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="若响应 \`Content-Type\` 使用非 \`utf-8\` 字符集（或缺失字符集参数），必须按 \`502 upstream_execution_failed\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response charset utf-8 fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response charset utf-8 fail-closed clause is present"
