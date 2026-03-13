#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-skip-shellcheck-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

set +e
QUICK_GATE_SKIP_SHELLCHECK=maybe bash "$SCRIPT" "$ROOT/scripts" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for invalid QUICK_GATE_SKIP_SHELLCHECK, got: $rc" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if ! grep -Fq -- "QUICK_GATE_SKIP_SHELLCHECK must be 0 or 1" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing invalid QUICK_GATE_SKIP_SHELLCHECK guard message" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

echo "[PASS] quick_gate rejects invalid QUICK_GATE_SKIP_SHELLCHECK values"
