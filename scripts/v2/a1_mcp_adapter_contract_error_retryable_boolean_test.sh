#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq "error.retryable" "$SPEC"; then
  echo "[FAIL] missing MCP adapter error.retryable field requirement" >&2
  exit 1
fi

if ! grep -Fq 'error.retryable`（boolean' "$SPEC"; then
  echo "[FAIL] missing MCP adapter boolean typing for error.retryable" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter error.retryable boolean contract is present"
