#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260303-0001",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "trnm-vision-base",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "v1.0.0"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-03T09:00:00Z",
    "provenance_index": "prov:lane-dae:task-20260303-0001",
    "privacy_tier": "public"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for public privacy tier carrying provenance_index" >&2
  exit 1
fi

if ! grep -Fq "provenance.forbidden field for conditional policy: provenance_index" <<<"$output"; then
  echo "[FAIL] missing explicit conditional-forbidden failure for provenance_index" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects provenance_index when privacy_tier is public"
