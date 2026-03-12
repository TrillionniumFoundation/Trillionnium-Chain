#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-non-directory-target.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

NOT_A_DIR="$TMP_DIR/not-a-dir"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"
printf 'echo hi\n' >"$NOT_A_DIR"

set +e
QUICK_GATE_SKIP_SHELLCHECK=1 \
  bash "$SCRIPT" "$NOT_A_DIR" >"$STDOUT_LOG" 2>"$STDERR_LOG"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for non-directory target path, got: $rc" >&2
  cat "$STDOUT_LOG" >&2 || true
  cat "$STDERR_LOG" >&2 || true
  exit 1
fi

if ! grep -Fq -- "[quick-gate][FAIL] target path is not a directory: $NOT_A_DIR" "$STDERR_LOG"; then
  echo "[FAIL] missing non-directory target guard message" >&2
  cat "$STDERR_LOG" >&2 || true
  exit 1
fi

if grep -Fq -- '[quick-gate] script_count=' "$STDOUT_LOG"; then
  echo "[FAIL] quick gate should fail before reporting script_count for a non-directory target path" >&2
  cat "$STDOUT_LOG" >&2 || true
  exit 1
fi

echo "[PASS] quick gate fails closed on non-directory target paths"
