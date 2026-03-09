#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="非 JSON 响应视为协议违约并按 \`502 upstream_execution_failed\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response Content-Type fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response Content-Type fail-closed clause is present"
