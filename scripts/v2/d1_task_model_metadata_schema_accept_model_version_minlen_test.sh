#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-model-version-minlen",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "v"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-03T06:45:00Z",
    "provenance_index": "prov:lane-dae:task-20260303-model-version-minlen",
    "privacy_tier": "internal"
  }
}
JSON

output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"

if ! grep -Fq "[PASS] D1 task/model metadata schema gate" <<<"$output"; then
  echo "[FAIL] expected schema gate pass at model.version minLength boundary" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate accepts model.version minLength=1 boundary"
