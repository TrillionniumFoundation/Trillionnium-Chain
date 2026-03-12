#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-summary-path-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
SUMMARY_DIR="$TMP_DIR/summary-dir"
mkdir -p "$SUMMARY_DIR"

set +e
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY_DIR" \
  bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] validator accepted directory summary path" >&2
  exit 1
fi

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for directory summary path, got: $rc" >&2
  exit 1
fi

if ! grep -Fq -- "WORKFLOW_SCRIPT_REF_SUMMARY_PATH points to a directory" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing directory summary path guard message" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

echo "[PASS] workflow script ref validator rejects directory summary paths"
