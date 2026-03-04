#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

integrity_clause='请求完整性：`X-TRNM-Body-SHA256`（请求体 SHA-256 小写 hex）；与服务端重算不一致按 `400 schema_invalid` fail-closed'
if ! grep -Fq "$integrity_clause" "$SPEC"; then
  echo "[FAIL] missing request body SHA-256 integrity fail-closed clause" >&2
  exit 1
fi

if ! grep -Fq '非法 schema：`400 schema_invalid`' "$SPEC"; then
  echo "[FAIL] missing schema_invalid error contract for integrity violations" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter body SHA-256 integrity fail-closed clauses are present"
