#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-non-directory-root.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

NOT_A_DIR="$TMP_DIR/not-a-dir"
printf 'name: not-a-directory\n' >"$NOT_A_DIR"

set +e
WORKFLOW_ROOT="$NOT_A_DIR" bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 when WORKFLOW_ROOT is a file, got: $rc" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if ! grep -Fq -- "workflow root is not a directory: $NOT_A_DIR" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing non-directory WORKFLOW_ROOT guard message" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if [[ -s "$TMP_DIR/stdout.log" ]]; then
  echo "[FAIL] expected empty stdout for non-directory WORKFLOW_ROOT guard" >&2
  cat "$TMP_DIR/stdout.log" >&2 || true
  exit 1
fi

echo "[PASS] workflow script ref validator fails closed when WORKFLOW_ROOT is not a directory"
