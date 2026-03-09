#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause='响应若出现多个 `X-TRNM-Schema-Version` 头（重复字段）必须按协议违约处理，并按 `502 upstream_execution_failed` fail-closed（禁止“取第一个/最后一个”容错）'
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter response duplicate schema-version header fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response duplicate schema-version header fail-closed clause is present"