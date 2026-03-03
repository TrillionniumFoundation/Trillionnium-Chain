#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq "409 idempotency_conflict" "$SPEC"; then
  echo "[FAIL] missing idempotency_conflict error code contract" >&2
  exit 1
fi

if ! grep -Fq "同键不同请求体" "$SPEC"; then
  echo "[FAIL] missing same-idempotency-key with different body fail-closed clause" >&2
  exit 1
fi

if ! grep -Fq '不得覆盖既有 `request_id -> task_id` 映射' "$SPEC"; then
  echo "[FAIL] missing non-overwrite mapping fail-closed clause for idempotency conflicts" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter idempotency conflict fail-closed clause is present"
