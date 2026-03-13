#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-summary-json-escape.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WEIRD_ROOT="$TMP_DIR/work\"flow"
mkdir -p "$WEIRD_ROOT" "$TMP_DIR/scripts"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$WEIRD_ROOT/test.yml" <<'YAML'
name: test
on: push
jobs:
  refs:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/example.sh
YAML

cat >"$TMP_DIR/scripts/example.sh" <<'EOF'
#!/usr/bin/env bash
echo ok
EOF
chmod +x "$TMP_DIR/scripts/example.sh"

(
  cd "$TMP_DIR"
  WORKFLOW_ROOT="$WEIRD_ROOT" \
  WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
    bash "$SCRIPT"
) >"$STDOUT_LOG" 2>"$STDERR_LOG"

python3 - <<'PY' "$SUMMARY" "$WEIRD_ROOT"
import json, sys
summary_path, workflow_root = sys.argv[1], sys.argv[2]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('workflow_root') != workflow_root:
    raise SystemExit(f"[FAIL] workflow_root not preserved in JSON summary: {data}")
if data.get('status') != 'ok':
    raise SystemExit(f"[FAIL] expected ok status in summary, got: {data}")
print('[PASS] workflow script ref validator JSON-escapes summary fields')
PY
