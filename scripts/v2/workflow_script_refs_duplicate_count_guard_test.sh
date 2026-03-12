#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-dup-guard.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT" "$TMP_DIR/scripts"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$TMP_DIR/scripts/shared_gate.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo ok
SH
chmod +x "$TMP_DIR/scripts/shared_gate.sh"

cat >"$WORKFLOW_ROOT/alpha.yml" <<'YAML'
name: alpha
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/shared_gate.sh
YAML

cat >"$WORKFLOW_ROOT/beta.yml" <<'YAML'
name: beta
on: workflow_dispatch
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/shared_gate.sh
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
    raise SystemExit(f"[FAIL] expected workflow_count=2, got: {data}")
if int(data.get('script_ref_total_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected duplicate refs to count toward script_ref_total_count=2, got: {data}")
if int(data.get('script_ref_count', 0)) != 1:
    raise SystemExit(f"[FAIL] expected duplicate refs to dedupe to script_ref_count=1, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
if '[workflow-ref] script_ref_total_count=2' not in stdout:
    raise SystemExit('[FAIL] missing script_ref_total_count log line in stdout')
if '[workflow-ref] script_ref_count=1' not in stdout:
    raise SystemExit('[FAIL] missing deduped script_ref_count log line in stdout')
print('[PASS] workflow script ref validator keeps duplicate total-vs-unique accounting stable')
PY
