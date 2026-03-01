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
    "model_id": "llama-70b ",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "v1"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-02T01:40:00Z",
    "provenance_index": "prov:lane-dae:task-20260302-0001",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for trailing-space model.model_id" >&2
  exit 1
fi

if ! grep -Fq "model.model_id does not match pattern ^\\S(?:.*\\S)?$" <<<"$output"; then
  echo "[FAIL] missing explicit edge-whitespace pattern error for model.model_id" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects model.model_id with trailing space"
