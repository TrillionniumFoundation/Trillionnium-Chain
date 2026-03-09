#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

# "prov:" (5 chars) + 128 payload chars = 133 total string length.
# The schema pattern enforces payload length 8..128; this case validates the
# upper boundary is accepted (not only overflow rejected).
cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260301-0011",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-01T01:20:00Z",
    "provenance_index": "prov:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "privacy_tier": "internal"
  }
}
JSON

output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
if ! grep -Fq "[PASS] D1 task/model metadata schema gate" <<<"$output"; then
  echo "[FAIL] expected schema gate pass at provenance_index max boundary" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D2 schema gate accepts provenance_index payload length=128 boundary"
