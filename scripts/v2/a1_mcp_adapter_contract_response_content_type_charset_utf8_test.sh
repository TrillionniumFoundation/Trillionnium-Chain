#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="响应内容类型：\`Content-Type: application/json; charset=utf-8\`"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response Content-Type charset=utf-8 clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response Content-Type explicitly requires application/json; charset=utf-8"
