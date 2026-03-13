#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-missing-target.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

MISSING_DIR="$TMP_DIR/does-not-exist"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

set +e
QUICK_GATE_SKIP_SHELLCHECK=1 \
  bash "$SCRIPT" "$MISSING_DIR" >"$STDOUT_LOG" 2>"$STDERR_LOG"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for missing target directory, got: $rc" >&2
  cat "$STDOUT_LOG" >&2 || true
  cat "$STDERR_LOG" >&2 || true
  exit 1
fi

if ! grep -Fq -- "[quick-gate][FAIL] target directory not found: $MISSING_DIR" "$STDERR_LOG"; then
  echo "[FAIL] missing target directory guard message" >&2
  cat "$STDERR_LOG" >&2 || true
  exit 1
fi

if grep -Fq -- '[quick-gate] script_count=' "$STDOUT_LOG"; then
  echo "[FAIL] quick gate should fail before reporting script_count for a missing target dir" >&2
  cat "$STDOUT_LOG" >&2 || true
  exit 1
fi

echo "[PASS] quick gate fails closed on missing target directories"
