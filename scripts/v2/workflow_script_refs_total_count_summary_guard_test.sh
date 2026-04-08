#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-total-count.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$WORKFLOW_ROOT/dup-refs.yml" <<'YAML'
name: dup-refs-summary-guard
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: |
          ./scripts/quick_gate_shell.sh
          ./scripts/quick_gate_shell.sh scripts
          python3 scripts/summarize_aggressive_profile.py
          cd trillionnium
          ./scripts/check_bft_4node_smoke.sh
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
if int(data.get('script_ref_total_count', 0)) != 4:
    raise SystemExit(f"[FAIL] expected total duplicate-aware ref count 4, got: {data}")
if int(data.get('script_ref_count', 0)) != 3:
    raise SystemExit(f"[FAIL] expected unique ref count 3, got: {data}")
if int(data.get('non_dot_script_ref_total_count', 0)) != 1:
    raise SystemExit(f"[FAIL] expected non-dot total ref count 1, got: {data}")
if int(data.get('non_dot_script_ref_count', 0)) != 1:
    raise SystemExit(f"[FAIL] expected non-dot unique ref count 1, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
if '[workflow-ref] script_ref_total_count=4' not in stdout:
    raise SystemExit('[FAIL] missing total ref count log line in stdout')
if '[workflow-ref] non_dot_script_ref_total_count=1' not in stdout:
    raise SystemExit('[FAIL] missing non-dot total ref count log line in stdout')
print('[PASS] workflow script ref validator reports total/unique refs and non-dot workflow script refs')
PY
