#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause='`X-TRNM-Request-ID` 必须为去首尾空白后的非空字符串；出现前后空白或空串按 `400 schema_invalid` fail-closed'
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter request-id trimmed non-empty fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter request-id trimmed non-empty fail-closed clause is present"
