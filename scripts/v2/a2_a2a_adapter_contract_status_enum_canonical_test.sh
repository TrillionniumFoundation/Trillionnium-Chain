#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$ROOT/docs/agent/a2a_adapter_contract_v1.md"

if [[ ! -f "$SPEC" ]]; then
  echo "[FAIL] missing A2A adapter contract spec: $SPEC" >&2
  exit 1
fi

expected='`accepted|rejected|settled`'
if ! grep -Fq -- "$expected" "$SPEC"; then
  echo "[FAIL] missing canonical A2 response status enum: $expected" >&2
  exit 1
fi

echo "[PASS] A2 A2A adapter contract keeps canonical response status enum (accepted|rejected|settled)"
