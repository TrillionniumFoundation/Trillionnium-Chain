#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-workflow-file-count.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$WORKFLOW_ROOT/one.yml" <<'YAML'
name: one
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/quick_gate_shell.sh
YAML

cat >"$WORKFLOW_ROOT/two.yml" <<'YAML'
name: two
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: python3 ./scripts/summarize_aggressive_profile.py
YAML

WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=1 \
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" >"$STDOUT_LOG" 2>"$STDERR_LOG"

python3 - <<'PY' "$SUMMARY" "$STDOUT_LOG"
import json, sys
summary_path, stdout_path = sys.argv[1], sys.argv[2]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'ok':
    raise SystemExit(f"[FAIL] expected ok status, got: {data}")
if int(data.get('workflow_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected workflow_count=2, got: {data}")
if int(data.get('workflow_file_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected workflow_file_count=2, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
if '[workflow-ref] workflow_count=2' not in stdout:
    raise SystemExit('[FAIL] missing workflow_count log line in stdout')
print('[PASS] workflow script ref validator exposes workflow_file_count alias in summary JSON')
PY
