#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_clause="请求必须携带：\`X-TRNM-Timestamp\`（RFC3339 UTC），允许时钟偏差 ≤ 300 秒；超窗请求按 \`401 capability_invalid\` fail-closed"
if ! grep -Fq "$required_clause" "$SPEC"; then
  echo "[FAIL] missing MCP adapter timestamp RFC3339 UTC + skew fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter timestamp clause remains RFC3339 UTC + ≤300s skew fail-closed"
