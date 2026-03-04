#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/a2a_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing A2A adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq "响应内容类型：\`Content-Type: application/json; charset=utf-8\`；非 JSON 响应按 \`502 upstream_execution_failed\` fail-closed" "$SPEC"; then
  echo "[FAIL] missing A2A adapter response Content-Type fail-closed clause" >&2
  exit 1
fi

echo "[PASS] A2 A2A adapter response Content-Type fail-closed clause is present"
