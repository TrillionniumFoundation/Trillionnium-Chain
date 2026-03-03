#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

nonce_binding_clause='Nonce 绑定：`X-TRNM-Nonce` 必须绑定 `request_id + X-TRNM-Body-SHA256`；同一 request_id 出现不同 nonce 也必须按 409 replay_detected fail-closed'
if ! grep -Fq "$nonce_binding_clause" "$SPEC"; then
  echo "[FAIL] missing nonce binding + replay_detected fail-closed clause" >&2
  exit 1
fi

if ! grep -Fq '防重放冲突：`409 replay_detected`（同一 `request_id` 出现重复 `X-TRNM-Nonce` 必须拒绝）' "$SPEC"; then
  echo "[FAIL] missing replay_detected error contract for nonce anti-replay" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter nonce binding + anti-replay fail-closed clauses are present"
