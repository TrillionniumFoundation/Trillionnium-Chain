#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq '请求头 `X-TRNM-Request-ID` 必须与请求体 `request_id` 严格一致；不一致按 `400 schema_invalid` fail-closed' "$SPEC"; then
  echo "[FAIL] missing request header/body request_id parity fail-closed rule" >&2
  exit 1
fi

echo "[PASS] request header/body request_id parity fail-closed rule is documented"
