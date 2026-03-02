#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"
TMP_JSON="$(mktemp)"
trap 'rm -f "$TMP_JSON"' EXIT

cat >"$TMP_JSON" <<'JSON'
{
  "task_id": "task-20260303-0001",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt 4.1",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:trn:lane-dae-01",
    "produced_at": "2026-03-03T04:00:00Z",
    "provenance_index": "prov:lane-dae:task-20260303-0001",
    "privacy_tier": "restricted"
  }
}
JSON

set +e
output="$(METADATA_FILE="$TMP_JSON" "$GATE" 2>&1)"
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit when model.model_id contains internal whitespace" >&2
  exit 1
fi

if ! grep -Fq "model.model_id does not match pattern" <<<"$output"; then
  echo "[FAIL] expected pattern mismatch for model.model_id, got:" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects model.model_id with internal whitespace"
