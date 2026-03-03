#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/a2a_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing A2A adapter contract spec: $SPEC" >&2
  exit 1
fi

if ! grep -Fq -- "响应必须回显：X-TRNM-Request-ID（与请求值逐字节一致）" "$SPEC"; then
  echo "[FAIL] missing A2A adapter exact request-id echo clause" >&2
  exit 1
fi

if ! grep -Fq -- '502 request_id_mismatch' "$SPEC"; then
  echo "[FAIL] missing A2A adapter fail-closed error code for request-id mismatch" >&2
  exit 1
fi

echo "[PASS] A2 A2A adapter enforces exact request-id echo + fail-closed mismatch error"
