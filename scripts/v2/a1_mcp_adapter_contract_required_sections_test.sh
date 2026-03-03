#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/mcp_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing MCP adapter contract spec: $SPEC" >&2
  exit 1
fi

required_headers=(
  "## 1. 目标与范围"
  "## 2. 传输与鉴权"
  "## 3. 最小请求/响应语义"
  "## 4. 错误模型（Fail-Closed）"
  "## 5. 验收与证据"
  "## 6. 回滚方案（Reversible）"
)

for header in "${required_headers[@]}"; do
  if ! grep -Fq "$header" "$SPEC"; then
    echo "[FAIL] missing required header: $header" >&2
    exit 1
  fi
done

guard_phrases=(
  "request_id"
  "task_id"
  "provenance_fingerprint"
  "Idempotency-Key"
  "X-TRNM-Nonce"
  "request_id + X-TRNM-Body-SHA256"
  "同一 request_id 出现不同 nonce 也必须按 409 replay_detected fail-closed"
  "X-TRNM-Request-ID"
  "响应必须回显：X-TRNM-Schema-Version: mcp-adapter-v1"
  "响应必须回显：X-TRNM-Request-ID"
  "错误响应（4xx/5xx）也必须回显"
  "X-TRNM-Trace-ID"
  "trace_id"
  "X-TRNM-Timestamp"
  "X-TRNM-Schema-Version"
  "X-TRNM-Body-SHA256"
  "SHA-256 小写 hex"
  "Content-Type: application/json"
  "Content-Type: application/json; charset=utf-8"
  "Authorization: Bearer <capability_token>"
  "mcp-adapter-v1"
  "时钟偏差 ≤ 300 秒"
  "协议版本与适配器传输层记录"
  "409 idempotency_conflict"
  "409 replay_detected"
  "同一键值 + 同一请求体必须幂等返回同一"
  "同键不同请求体"
  "error.code"
  "error.message"
  "error.retryable"
  "trnm-agent mcp-adapter rollback"
  "--root-cause-tag"
)

for phrase in "${guard_phrases[@]}"; do
  if ! grep -Fq -- "$phrase" "$SPEC"; then
    echo "[FAIL] missing required guard phrase: $phrase" >&2
    exit 1
  fi
done

echo "[PASS] A1 MCP adapter contract spec includes required sections + rollback/evidence guard phrases"
