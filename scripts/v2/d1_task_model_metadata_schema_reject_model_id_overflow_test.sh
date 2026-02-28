#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

META="$TMP_DIR/metadata.json"

python3 - <<'PY' > "$META"
import json

payload = {
  "task_id": "task-20260301-0014",
  "task_type": "inference",
  "input_hash": "a" * 64,
  "model": {
    "model_id": "m" * 129,
    "model_digest": "b" * 64,
    "version": "v1"
  },
  "provenance": {
    "producer_did": "did:trn:producer-001",
    "produced_at": "2026-03-01T05:10:00Z",
    "provenance_index": "prov:lane-dae:task-20260301-0014",
    "privacy_tier": "internal"
  }
}
print(json.dumps(payload))
PY

set +e
output="$(SCHEMA_FILE="$ROOT/docs/schemas/task_model_metadata.schema.json" METADATA_FILE="$META" "$ROOT/scripts/v2/d1_task_model_metadata_schema_gate.sh" 2>&1)"
status=$?
set -e

if [ "$status" -eq 0 ]; then
  echo "[FAIL] expected non-zero exit for model.model_id overflow" >&2
  echo "$output" >&2
  exit 1
fi

if ! grep -Fq "model.model_id longer than maxLength=128" <<<"$output"; then
  echo "[FAIL] missing explicit maxLength error for model.model_id" >&2
  echo "$output" >&2
  exit 1
fi

echo "[PASS] D1 schema gate rejects model.model_id overflow"
