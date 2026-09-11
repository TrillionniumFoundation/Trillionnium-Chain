#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"
WF="$ROOT/.github/workflows/rust-l1-nightly-health.yml"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }
[[ -f "$WF" ]] || { echo "[FAIL] missing workflow: $WF" >&2; exit 1; }

required_py_refs=(
  './scripts/executor_profile_report.py'
  './scripts/render_nightly_summary.py'
  './scripts/suggest_auto_adaptive_thresholds.py'
  './scripts/summarize_aggressive_profile.py'
  './scripts/v2/pr6_daily_security_summary.py'
  './scripts/v2/pr9_weekly_alert_governance.py'
)

for ref in "${required_py_refs[@]}"; do
  if ! grep -Fq -- "$ref" "$WF"; then
    echo "[FAIL] expected python workflow ref missing from nightly workflow: $ref" >&2
    exit 1
  fi
done

if ! grep -Fq -- "grep -Eo '(\\./scripts|scripts|trillionnium/scripts)/[[:alnum:]_./-]+\\.(sh|py)'" "$SCRIPT"; then
  echo "[FAIL] validate_workflow_script_refs.sh must scan ./scripts, scripts, and trillionnium/scripts refs for both .sh and .py workflow refs" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-py-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
SUMMARY="$TMP_DIR/summary.json"

WORKFLOW_SCRIPT_REF_STRICT=1 \
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"

python3 - <<'PY' "$SUMMARY"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'ok':
    raise SystemExit(f"[FAIL] expected ok status, got: {data}")
if int(data.get('script_ref_count', 0)) < 6:
    raise SystemExit(f"[FAIL] expected python-aware script_ref_count, got: {data}")
print('[PASS] workflow script ref validator covers python references used by workflows')
PY
