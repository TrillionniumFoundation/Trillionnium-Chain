#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260302-2030",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "producer_did": "did:trnm:org:lane-dae",
    "produced_at": "2026-03-02T12:34:56.1234567Z",
    "provenance_index": "prov:lane-dae:task-20260302-2030",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for produced_at fractional seconds longer than 6 digits" >&2
  exit 1
fi

if ! grep -Fq "provenance.produced_at does not match pattern" <<<"$output"; then
  echo "[FAIL] missing explicit produced_at UTC-fraction precision pattern error" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects provenance produced_at with >6 fractional digits"