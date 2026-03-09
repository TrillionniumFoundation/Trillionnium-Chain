#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260303-1417",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:key:z6Mkexample123",
    "produced_at": "2026-03-03T06:17:00Z",
    "provenance_index": "prov:LaneDae:task-20260303-1417",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit when internal privacy_tier uses invalid provenance_index pattern" >&2
  exit 1
fi

if ! grep -Fq "provenance.provenance_index does not match pattern" <<<"$output"; then
  echo "[FAIL] missing explicit provenance_index pattern validation failure" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D3 schema gate rejects malformed provenance_index for internal privacy tier"
