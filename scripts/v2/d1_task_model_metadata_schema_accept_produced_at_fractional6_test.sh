#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260302-0001",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-02T03:21:45.123456Z",
    "provenance_index": "prov:lane-dae:task-20260302-0001",
    "privacy_tier": "internal"
  }
}
JSON

METADATA_FILE="$tmp_file" "$GATE"

echo "[PASS] D1 schema gate accepts provenance produced_at with 6-digit fractional seconds"
