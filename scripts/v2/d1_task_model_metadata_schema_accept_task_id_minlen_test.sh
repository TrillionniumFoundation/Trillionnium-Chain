#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "a",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "v1"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-02T00:00:00Z",
    "provenance_index": "prov:lane-dae:task-20260302-0001",
    "privacy_tier": "internal"
  }
}
JSON

output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"

if ! grep -Fq "[PASS] D1 task/model metadata schema gate" <<<"$output"; then
  echo "[FAIL] expected schema gate pass for task_id minLength boundary" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate accepts task_id minLength boundary (1 char)"