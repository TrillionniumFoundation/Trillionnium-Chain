#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="\`status\` 必须为上述小写枚举之一；出现大小写漂移或未知状态（如 \`Accepted\` / \`done\`）按 \`502 upstream_execution_failed\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response status enum fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response status enum fail-closed clause is present"
