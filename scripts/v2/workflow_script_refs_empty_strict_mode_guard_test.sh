#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-empty-strict-mode.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"
cat >"$WORKFLOW_ROOT/test.yml" <<'EOF'
name: test
on: push
jobs:
  noop:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no script refs here"
EOF

set +e
WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=1 \
  bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] validator stayed green in strict mode with zero workflow script refs" >&2
  exit 1
fi

if [[ "$rc" -ne 1 ]]; then
  echo "[FAIL] expected exit code 1 in strict mode, got: $rc" >&2
  exit 1
fi

if ! grep -Fq -- "[workflow-ref][WARN] no workflow script references found in workflows" "$TMP_DIR/stdout.log"; then
  echo "[FAIL] missing empty-ref warning output" >&2
  cat "$TMP_DIR/stdout.log" >&2
  exit 1
fi

if ! grep -Fq -- "[workflow-ref] status=fail strict_mode=1" "$TMP_DIR/stdout.log"; then
  echo "[FAIL] missing strict-mode fail status line for empty workflow refs" >&2
  cat "$TMP_DIR/stdout.log" >&2
  exit 1
fi

echo "[PASS] workflow script ref validator fails closed in strict mode when workflows contain zero script refs"
