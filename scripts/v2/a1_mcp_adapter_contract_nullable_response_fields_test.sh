#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_nullable_lines=(
  "- \`settlement_ref\`（可空）"
  "- \`provenance_fingerprint\`（可空，遵循隐私策略）"
)

for line in "${required_nullable_lines[@]}"; do
  if ! grep -Fq -- "$line" "$SPEC"; then
    echo "[FAIL] MCP adapter response nullable contract drifted: missing line -> $line" >&2
    exit 1
  fi
done

echo "[PASS] A1 MCP adapter nullable response fields remain canonical and fail-closed"
