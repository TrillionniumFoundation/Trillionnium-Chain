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

strict_token_clause="\`X-TRNM-Schema-Version\` 回显值必须为未加引号的精确 token \`mcp-adapter-v1\`（禁止 \`\"mcp-adapter-v1\"\`、前后空白或参数拼接）；否则按 \`502 upstream_execution_failed\` fail-closed"
if ! grep -Fq "$strict_token_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter strict schema-version token clause" >&2
  exit 1
fi

duplicate_header_clause="响应若出现多个 \`X-TRNM-Schema-Version\` 头（重复字段）必须按协议违约处理，并按 \`502 upstream_execution_failed\` fail-closed（禁止“取第一个/最后一个”容错）"
if ! grep -Fq "$duplicate_header_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter duplicate schema-version header fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response schema-version echo fail-closed clauses are present"
