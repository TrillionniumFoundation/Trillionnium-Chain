#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq '错误响应（4xx/5xx）也必须使用 `Content-Type: application/json; charset=utf-8`；非 JSON 错误体按 `502 upstream_execution_failed` fail-closed' "$SPEC"; then
  echo "[FAIL] missing MCP adapter error response Content-Type fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter error response Content-Type fail-closed clause is present"
