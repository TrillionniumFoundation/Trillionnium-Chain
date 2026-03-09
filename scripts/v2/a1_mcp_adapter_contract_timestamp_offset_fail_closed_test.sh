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

if ! grep -Fq '必须为 `Z` 结尾的 UTC 时间戳' "$SPEC"; then
  echo "[FAIL] missing explicit UTC Z-suffix requirement for timestamp" >&2
  exit 1
fi

if ! grep -Fq '禁止 `+08:00`/`-05:00` 等偏移格式' "$SPEC"; then
  echo "[FAIL] missing explicit offset timezone reject rule" >&2
  exit 1
fi

if ! grep -Fq '偏移时区按 `400 schema_invalid` fail-closed' "$SPEC"; then
  echo "[FAIL] missing fail-closed mapping for timezone-offset timestamp" >&2
  exit 1
fi

echo "[PASS] A1 MCP adapter timestamp offset fail-closed contract is present"
