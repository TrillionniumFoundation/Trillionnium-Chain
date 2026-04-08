#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-empty-warning-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$WORKFLOW_ROOT/no-script-refs.yml" <<'YAML'
name: no-script-refs
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no script refs here"
YAML

WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=0 \
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" >"$STDOUT_LOG" 2>"$STDERR_LOG"

python3 - <<'PY' "$SUMMARY" "$STDOUT_LOG" "$STDERR_LOG"
import json, sys
summary_path, stdout_path, stderr_path = sys.argv[1:4]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'warn':
    raise SystemExit(f"[FAIL] expected warn status for non-strict empty-ref workflow, got: {data}")
if int(data.get('script_ref_total_count', 0)) != 0:
    raise SystemExit(f"[FAIL] expected script_ref_total_count=0, got: {data}")
if int(data.get('empty_ref_count', -1)) != 1:
    raise SystemExit(f"[FAIL] expected empty_ref_count=1 for empty-ref workflow summary, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
stderr = open(stderr_path, 'r', encoding='utf-8').read()
expected = '[workflow-ref][WARN] no workflow script references found in workflows (expected ./scripts, scripts, or trillionnium/scripts .sh/.py refs)'
if expected not in stdout:
    raise SystemExit('[FAIL] missing aligned empty-ref warning in stdout')
if '[workflow-ref] empty_ref_count=1' not in stdout:
    raise SystemExit('[FAIL] missing empty_ref_count log line in stdout')
if '[workflow-ref] status=warn strict_mode=0' not in stdout:
    raise SystemExit('[FAIL] missing non-strict warn status line in stdout')
if stderr.strip():
    raise SystemExit(f"[FAIL] expected empty stderr, got: {stderr}")
print('[PASS] workflow script ref validator reports non-strict empty-ref workflows as warnings with aligned output')
PY
