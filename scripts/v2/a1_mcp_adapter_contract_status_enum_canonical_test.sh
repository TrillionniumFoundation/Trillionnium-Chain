#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

canonical="- \`status\`（\`accepted|rejected|settled\`）"
if ! grep -Fq -- "$canonical" "$SPEC"; then
  echo "[FAIL] MCP adapter response status enum drifted from canonical contract: accepted|rejected|settled" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter response status enum remains canonical and fail-closed"
