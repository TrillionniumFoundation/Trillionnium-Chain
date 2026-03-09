#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

sample_json="$(mktemp)"
trap 'rm -f "$sample_json"' EXIT

cat >"$sample_json" <<'JSON'
{
  "task_id": "task-lane-dae-public-null-index",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "openai/gpt-4.1-mini",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026-03-03"
  },
  "provenance": {
    "producer_did": "did:trn:agent-public",
    "produced_at": "2026-03-03T10:34:00Z",
    "provenance_index": null,
    "privacy_tier": "public"
  }
}
JSON

set +e
output="$(METADATA_FILE="$sample_json" "$GATE" 2>&1)"
status=$?
set -e

if [ $status -eq 0 ]; then
  echo "[FAIL] expected non-zero exit when public privacy_tier carries null provenance_index" >&2
  exit 1
fi

if ! grep -Fq "provenance.forbidden field for conditional policy: provenance_index" <<<"$output"; then
  echo "[FAIL] missing explicit conditional-policy error for public null provenance_index" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D3 schema gate rejects null provenance_index for public privacy tier"
