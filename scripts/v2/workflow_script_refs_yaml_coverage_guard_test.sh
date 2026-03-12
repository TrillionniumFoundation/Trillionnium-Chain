#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-yaml-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT" "$TMP_DIR/scripts"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$TMP_DIR/scripts/quick_gate_shell.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
SH
chmod +x "$TMP_DIR/scripts/quick_gate_shell.sh"

cat >"$TMP_DIR/scripts/summarize_aggressive_profile.py" <<'PY'
print('ok')
PY

cat >"$WORKFLOW_ROOT/alpha.yml" <<'YAML'
name: alpha
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/quick_gate_shell.sh
YAML

cat >"$WORKFLOW_ROOT/beta.yaml" <<'YAML'
name: beta
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: python3 ./scripts/summarize_aggressive_profile.py
YAML

(
  cd "$TMP_DIR"
  WORKFLOW_ROOT="workflows" \
  WORKFLOW_SCRIPT_REF_STRICT=1 \
  WORKFLOW_SCRIPT_REF_SUMMARY_PATH="summary.json" \
    bash "$SCRIPT" >"stdout.log" 2>"stderr.log"
)

python3 - <<'PY' "$SUMMARY" "$STDOUT_LOG"
import json, sys
summary_path, stdout_path = sys.argv[1], sys.argv[2]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'ok':
    raise SystemExit(f"[FAIL] expected ok status, got: {data}")
if int(data.get('workflow_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected workflow_count=2 across .yml + .yaml, got: {data}")
if int(data.get('script_ref_total_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected script_ref_total_count=2 across .yml + .yaml, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
if '[workflow-ref] workflow_count=2' not in stdout:
    raise SystemExit('[FAIL] missing workflow_count log line in stdout')
if '[workflow-ref] script_ref_total_count=2' not in stdout:
    raise SystemExit('[FAIL] missing script_ref_total_count log line in stdout')
print('[PASS] workflow script ref validator covers both .yml and .yaml workflow files')
PY
