#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

# Directory path must be rejected with explicit diagnostic.
set +e
QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$TMP_DIR" bash "$SCRIPT" "$ROOT/scripts" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
code=$?
set -e

if [[ "$code" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 for directory summary path, got: $code" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if ! grep -q "QUICK_GATE_SUMMARY_PATH points to a directory" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] expected directory guard diagnostic missing" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

# Valid file path should pass and produce parseable JSON summary.
SUMMARY_OK="$TMP_DIR/summary.json"
QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$SUMMARY_OK" bash "$SCRIPT" "$ROOT/scripts" >"$TMP_DIR/stdout-ok.log" 2>"$TMP_DIR/stderr-ok.log"
python3 - <<'PY' "$SUMMARY_OK"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
assert data.get('status') == 'ok', data
print('ok')
PY

echo "[PASS] quick_gate summary path guard test"