#!/usr/bin/env bash
set -euo pipefail

# NOTE: legacy filename kept for compatibility with existing CI hooks.
# Actual contract: internal privacy_tier MUST provide provenance_index.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260301-2012",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:key:z6Mkexample123",
    "produced_at": "2026-03-01T03:35:00Z",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
status=$?
set -e

if [[ $status -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit when internal privacy_tier omits provenance_index" >&2
  exit 1
fi

if ! grep -Fq "provenance.missing required field: provenance_index" <<<"$output"; then
  echo "[FAIL] missing explicit provenance_index required error for internal tier" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D3 schema gate rejects missing provenance_index for internal privacy tier"
