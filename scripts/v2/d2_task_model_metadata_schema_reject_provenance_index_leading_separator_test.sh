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
    "produced_at": "2026-03-02T08:50:00Z",
    "provenance_index": "prov:_lane-dae-20260302-0001",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for leading separator in provenance_index" >&2
  exit 1
fi

if ! grep -Fq "provenance.provenance_index does not match pattern ^prov:[a-z0-9](?:[a-z0-9]|[:_-](?=[a-z0-9])){6,126}[a-z0-9]$" <<<"$output"; then
  echo "[FAIL] missing explicit provenance_index pattern error" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D2 schema gate rejects provenance_index with leading separator"
