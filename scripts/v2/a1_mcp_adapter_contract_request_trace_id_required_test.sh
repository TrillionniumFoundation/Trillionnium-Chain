#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="请求必须携带：\`X-TRNM-Trace-ID\`（跨系统审计关联键，必须与审计导出中的 \`trace_id\` 一致）"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter request trace-id required clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter request trace-id required clause is present"
