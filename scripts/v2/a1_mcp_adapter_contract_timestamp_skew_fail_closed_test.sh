#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq "X-TRNM-Timestamp" "$SPEC"; then
  echo "[FAIL] missing X-TRNM-Timestamp request header contract" >&2
  exit 1
fi

if ! grep -Fq "允许时钟偏差 ≤ 300 秒" "$SPEC"; then
  echo "[FAIL] missing explicit timestamp clock-skew bound (<=300s)" >&2
  exit 1
fi

if ! grep -Fq '超窗请求按 `401 capability_invalid` fail-closed' "$SPEC"; then
  echo "[FAIL] missing fail-closed mapping for expired timestamp window" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter timestamp skew fail-closed contract is present"
