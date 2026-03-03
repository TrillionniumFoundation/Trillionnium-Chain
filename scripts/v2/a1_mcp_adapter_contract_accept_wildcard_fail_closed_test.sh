#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause='`Accept` 仅为通配符（如 `*/*` 或 `application/*`）不视为“显式包含 `application/json`”，必须按 `400 schema_invalid` fail-closed'
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter Accept wildcard fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter Accept wildcard fail-closed clause is present"
