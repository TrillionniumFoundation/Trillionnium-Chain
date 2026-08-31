#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"
WF="$ROOT/.github/workflows/trnm-merge-gates.yml"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }
[[ -f "$WF" ]] || { echo "[FAIL] missing workflow: $WF" >&2; exit 1; }

required_relative_refs=(
  './scripts/summarize_aggressive_profile.py'
  './scripts/analyze_aggressive_scan_correlation.py'
)

for ref in "${required_relative_refs[@]}"; do
  if ! grep -Fq -- "$ref" "$WF"; then
    echo "[FAIL] expected relative scripts/ workflow ref missing from trnm-merge-gates workflow: $ref" >&2
    exit 1
  fi
done

if ! grep -Fq -- "grep -Eo '(\\./trillionnium/scripts|\\./scripts|scripts|trillionnium/scripts)/[[:alnum:]_./-]+\\.(sh|py)'" "$SCRIPT"; then
  echo "[FAIL] validate_workflow_script_refs.sh must scan root and trillionnium script refs with and without ./ prefix" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-relative-scripts-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
SUMMARY="$TMP_DIR/summary.json"
WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"

cat >"$WORKFLOW_ROOT/relative-scripts.yml" <<'YAML'
name: relative-scripts-ref-guard
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: |
          python3 scripts/summarize_aggressive_profile.py
          python3 scripts/analyze_aggressive_scan_correlation.py
YAML

WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=0 \
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"

python3 - <<'PY' "$SUMMARY"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'warn':
    raise SystemExit(f"[FAIL] expected non-strict warning status, got: {data}")
if int(data.get('script_ref_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected exactly 2 relative scripts refs, got: {data}")
if int(data.get('non_dot_script_ref_total_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected non-dot total ref count 2, got: {data}")
if int(data.get('non_dot_script_ref_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected non-dot unique ref count 2, got: {data}")
print('[PASS] workflow script ref validator reports non-dot scripts/ refs without weakening strict mode')
PY
