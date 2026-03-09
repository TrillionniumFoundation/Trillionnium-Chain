#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/a2a_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing A2A adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq "请求内容类型：\`Content-Type: application/json\`" "$SPEC"; then
  echo "[FAIL] missing A2A adapter request Content-Type clause" >&2
  exit 1
fi

echo "[PASS] A2 A2A adapter request Content-Type clause is present"
