#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-workflow-root-log.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/custom-workflows"
mkdir -p "$WORKFLOW_ROOT"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$WORKFLOW_ROOT/one.yml" <<'YAML'
name: workflow-root-log-guard
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/quick_gate_shell.sh
YAML

WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=1 \
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" >"$STDOUT_LOG" 2>"$STDERR_LOG"

python3 - <<'PY' "$SUMMARY" "$STDOUT_LOG" "$WORKFLOW_ROOT"
import json, sys
summary_path, stdout_path, workflow_root = sys.argv[1:4]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'ok':
    raise SystemExit(f"[FAIL] expected ok status, got: {data}")
if data.get('workflow_root') != workflow_root:
    raise SystemExit(f"[FAIL] expected workflow_root {workflow_root!r}, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
expected = f'[workflow-ref] workflow_root={workflow_root}'
if expected not in stdout:
    raise SystemExit('[FAIL] missing workflow_root log line in stdout')
print('[PASS] workflow script ref validator logs workflow_root for deterministic debugging context')
PY
