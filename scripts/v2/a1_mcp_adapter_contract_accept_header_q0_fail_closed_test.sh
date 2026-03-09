#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause='`Accept` 中若 `application/json;q=0`（显式不可接受）必须视为不接受 JSON，并按 `400 schema_invalid` fail-closed'
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter Accept q=0 fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter Accept q=0 fail-closed clause is present"
