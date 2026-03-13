#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/validate_workflow_script_refs.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/workflow-ref-non-exec-strict-mode.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW_ROOT="$TMP_DIR/workflows"
mkdir -p "$WORKFLOW_ROOT" "$TMP_DIR/scripts"
SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

cat >"$WORKFLOW_ROOT/test.yml" <<'YAML'
name: test
on: push
jobs:
  refs:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/not_executable.sh
YAML

cat >"$TMP_DIR/scripts/not_executable.sh" <<'EOF'
#!/usr/bin/env bash
echo test
EOF
chmod 0644 "$TMP_DIR/scripts/not_executable.sh"

set +e
(
  cd "$TMP_DIR"
  WORKFLOW_ROOT="$WORKFLOW_ROOT" \
  WORKFLOW_SCRIPT_REF_STRICT=1 \
  WORKFLOW_SCRIPT_REF_SUMMARY_PATH="$SUMMARY" \
    bash "$SCRIPT"
) >"$STDOUT_LOG" 2>"$STDERR_LOG"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] validator stayed green in strict mode with a non-executable shell ref" >&2
  exit 1
fi

if [[ "$rc" -ne 1 ]]; then
  echo "[FAIL] expected exit code 1 in strict mode for non-executable shell ref, got: $rc" >&2
  exit 1
fi

if ! grep -Fq -- "[workflow-ref][WARN] referenced scripts without executable bit:" "$STDERR_LOG"; then
  echo "[FAIL] missing non-executable ref warning output" >&2
  cat "$STDERR_LOG" >&2
  exit 1
fi

if ! grep -Fq -- "./scripts/not_executable.sh -> scripts/not_executable.sh" "$STDERR_LOG"; then
  echo "[FAIL] missing offending non-executable script mapping in output" >&2
  cat "$STDERR_LOG" >&2
  exit 1
fi

if ! grep -Fq -- "[workflow-ref] status=fail strict_mode=1" "$STDOUT_LOG"; then
  echo "[FAIL] missing strict-mode fail status line for non-executable shell ref" >&2
  cat "$STDOUT_LOG" >&2
  exit 1
fi

python3 - <<'PY' "$SUMMARY"
import json, sys
summary_path = sys.argv[1]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('status') != 'fail':
    raise SystemExit(f"[FAIL] expected fail status in summary, got: {data}")
if int(data.get('missing_count', 0)) != 0:
    raise SystemExit(f"[FAIL] expected missing_count=0, got: {data}")
if int(data.get('non_exec_count', 0)) != 1:
    raise SystemExit(f"[FAIL] expected non_exec_count=1, got: {data}")
print('[PASS] workflow script ref validator hard-fails non-executable shell refs in strict mode')
PY
