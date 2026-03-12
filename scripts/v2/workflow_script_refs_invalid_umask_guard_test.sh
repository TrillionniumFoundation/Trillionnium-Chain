#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

set +e
UMASK=bad bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for invalid UMASK, got: $rc" >&2
  exit 1
fi

if ! grep -Fq -- "UMASK must be a 3- or 4-digit octal value" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing invalid UMASK guard message" >&2
  exit 1
fi

echo "[PASS] workflow script ref validator rejects invalid UMASK values"
