#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh"

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat >"$tmp_file" <<'JSON'
{
  "task_id": "task-20260301-0009",
  "task_type": "inference",
  "input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "model": {
    "model_id": "gpt-5.3-codex",
    "model_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version": "2026.03"
  },
  "provenance": {
    "provenance_index": "prov:did-uppercase-test",
    "producer_did": "did:KEY:z6Mkexample123",
    "produced_at": "2026-03-01T03:10:00Z",
    "privacy_tier": "internal"
  }
}
JSON

set +e
output="$(METADATA_FILE="$tmp_file" "$GATE" 2>&1)"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected non-zero exit for uppercase DID method" >&2
  exit 1
fi

if ! grep -Fq "provenance.producer_did does not match pattern" <<<"$output"; then
  echo "[FAIL] missing explicit producer_did pattern error" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects uppercase provenance producer_did method"
