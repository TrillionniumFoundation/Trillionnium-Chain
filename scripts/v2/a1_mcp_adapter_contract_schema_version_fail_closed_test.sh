#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clauses=(
  "X-TRNM-Schema-Version"
  "当前固定"
  "mcp-adapter-v1"
  "版本不匹配按"
  "400 schema_invalid"
  "响应必须回显：X-TRNM-Schema-Version: mcp-adapter-v1"
)

for clause in "${required_clauses[@]}"; do
  if ! grep -Fq -- "$clause" "$SPEC"; then
    echo "[FAIL] missing schema-version fail-closed clause: $clause" >&2
    exit 1
  fi
done

echo "[PASS] A1 MCP adapter schema-version fail-closed contract is pinned"
