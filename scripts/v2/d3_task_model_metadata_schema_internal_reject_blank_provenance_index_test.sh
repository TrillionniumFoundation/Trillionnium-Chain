#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260301-1114",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:key:z6Mkexample123",
    "produced_at": "2026-03-01T03:37:00Z",
    "provenance_index": "",
    "privacy_tier": "internal"
  }
}
JSON

if METADATA_FILE="$tmp_file" "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] D3 schema gate unexpectedly accepted blank provenance_index for internal tier" >&2
  exit 1
fi

echo "[PASS] D3 schema gate rejects blank provenance_index for internal privacy tier"
