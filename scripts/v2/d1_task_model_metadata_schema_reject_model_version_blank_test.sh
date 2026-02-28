#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260301-0019",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-lite",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "   "
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-01T06:45:00Z",
    "provenance_index": "prov:lane-dae:task-20260301-0019",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for whitespace-only model.version" >&2
  exit 1
fi

if ! grep -Fq "model.version does not match pattern ^.*\\S.*$" <<<"$output"; then
  echo "[FAIL] missing explicit non-whitespace pattern error for model.version" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects whitespace-only model.version"
