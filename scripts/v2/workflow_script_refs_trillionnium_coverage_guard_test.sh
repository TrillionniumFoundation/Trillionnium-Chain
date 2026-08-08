#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"
WF="$ROOT/.github/workflows/agent-user-phasea-gate.yml"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }
[[ -f "$WF" ]] || { echo "[FAIL] missing workflow: $WF" >&2; exit 1; }

required_direct_refs=(
  'trillionnium/scripts/run_agent_user_phasea_gate.sh'
  'trillionnium/scripts/run_phasea_fault_injection_suite.sh'
  'trillionnium/scripts/run_phasea_soak_gate.sh'
)

for ref in "${required_direct_refs[@]}"; do
  if ! grep -Fq -- "$ref" "$WF"; then
    echo "[FAIL] expected direct workflow ref missing from agent-user-phasea workflow: $ref" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-trnm-rust-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"
WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT"

cat >"$WORKFLOW_ROOT/direct-trnm-rust.yml" <<'YAML'
name: direct-trnm-rust-ref-guard
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cd trillionnium
          ./scripts/run_agent_user_phasea_gate.sh
          ./scripts/run_phasea_fault_injection_suite.sh
          ./scripts/run_phasea_soak_gate.sh
      - run: ./trillionnium/scripts/run_agent_user_phasea_gate.sh
YAML

WORKFLOW_ROOT="$WORKFLOW_ROOT" \
WORKFLOW_SCRIPT_REF_STRICT=1 \
WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" >"$STDOUT_LOG" 2>"$STDERR_LOG"

python3 - <<'PY' "$SUMMARY"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'ok':
    raise SystemExit(f"[FAIL] expected ok status, got: {data}")
if int(data.get('script_ref_count', 0)) != 4:
    raise SystemExit(f"[FAIL] expected exactly 4 direct trillionnium refs, got: {data}")
if int(data.get('non_dot_script_ref_count', 0)) != 0:
    raise SystemExit(f"[FAIL] ./trillionnium/scripts refs must stay relative and deterministic: {data}")
print('[PASS] workflow script ref validator covers both root-relative and working-directory-relative trillionnium scripts')
PY
