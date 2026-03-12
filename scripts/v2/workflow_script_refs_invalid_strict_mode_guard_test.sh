#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-invalid-strict-mode.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

set +e
WORKFLOW_SCRIPT_REF_STRICT=maybe bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for invalid WORKFLOW_SCRIPT_REF_STRICT, got: $rc" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if ! grep -Fq -- "WORKFLOW_SCRIPT_REF_STRICT must be 0 or 1" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing invalid WORKFLOW_SCRIPT_REF_STRICT guard message" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

echo "[PASS] workflow script ref validator rejects invalid strict-mode values"
