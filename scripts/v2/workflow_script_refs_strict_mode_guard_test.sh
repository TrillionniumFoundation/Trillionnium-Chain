#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-strict-mode.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"
cat >"$WORKFLOW_ROOT/test.yml" <<'EOF'
name: test
on: push
jobs:
  refs:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/does_not_exist.sh
EOF

set +e
WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=1 \
  bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] validator stayed green in strict mode with a missing script ref" >&2
  exit 1
fi

if [[ "$rc" -ne 1 ]]; then
  echo "[FAIL] expected exit code 1 in strict mode, got: $rc" >&2
  exit 1
fi

if ! grep -Fq -- "[workflow-ref][WARN] missing script references:" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing strict-mode missing-ref warning output" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

if ! grep -Fq -- "./scripts/does_not_exist.sh" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing offending script reference in output" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

if ! grep -Fq -- "[workflow-ref] status=fail strict_mode=1" "$TMP_DIR/stdout.log"; then
  echo "[FAIL] missing strict-mode fail status line" >&2
  cat "$TMP_DIR/stdout.log" >&2
  exit 1
fi

echo "[PASS] workflow script ref validator hard-fails missing refs in strict mode"
