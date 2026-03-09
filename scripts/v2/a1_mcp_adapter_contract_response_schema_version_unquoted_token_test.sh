#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause='`X-TRNM-Schema-Version` 回显值必须为未加引号的精确 token `mcp-adapter-v1`（禁止 `"mcp-adapter-v1"`、前后空白或参数拼接）；否则按 `502 upstream_execution_failed` fail-closed'
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response schema-version unquoted-token fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response schema-version unquoted token fail-closed clause is present"
