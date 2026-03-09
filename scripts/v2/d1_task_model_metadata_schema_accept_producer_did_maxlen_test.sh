#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

PRODUCER_DID="$(python3 - <<'PY'
prefix = 'did:trnm:'
print(prefix + ('a' * (128 - len(prefix))))
PY
)"

cat >"$tmp_file" <<JSON
{
  "task_id": "task-20260301-d1-producer-maxlen",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "v1"
  },
  "provenance": {
    "producer_did": "${PRODUCER_DID}",
    "produced_at": "2026-03-01T20:40:00Z",
    "provenance_index": "prov:lane-dae:task-20260301-2040",
    "privacy_tier": "internal"
  }
}
JSON

output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"

if ! grep -Fq "[PASS] D1 task/model metadata schema gate" <<<"$output"; then
  echo "[FAIL] expected schema gate pass at producer_did maxLength boundary" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate accepts producer_did maxLength=128 boundary"
