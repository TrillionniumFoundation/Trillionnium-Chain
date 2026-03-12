#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-explicit-skip-shellcheck.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TARGET_DIR="$TMP_DIR/target"
mkdir -p "$TARGET_DIR"
cat >"$TARGET_DIR/sample.sh" <<'EOF'
#!/usr/bin/env bash
echo ok
EOF
chmod +x "$TARGET_DIR/sample.sh"

SUMMARY="$TMP_DIR/summary.json"
QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$SUMMARY" bash "$SCRIPT" "$TARGET_DIR" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"

python3 - <<'PY' "$SUMMARY"
import json, sys
summary = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
if summary.get('shellcheck_requested') != 1:
    raise SystemExit(f"expected shellcheck_requested=1 for explicit skip, got {summary.get('shellcheck_requested')}")
if summary.get('skip_shellcheck') != 1:
    raise SystemExit(f"expected skip_shellcheck=1, got {summary.get('skip_shellcheck')}")
if summary.get('shellcheck_fallback_reason') != '':
    raise SystemExit(f"expected empty shellcheck_fallback_reason for explicit skip, got {summary.get('shellcheck_fallback_reason')!r}")
if summary.get('shellcheck_status') != 'skipped':
    raise SystemExit(f"expected shellcheck_status=skipped, got {summary.get('shellcheck_status')}")
if summary.get('status') != 'warn-shellcheck-skipped':
    raise SystemExit(f"expected status=warn-shellcheck-skipped, got {summary.get('status')}")
print('ok')
PY

if ! grep -Fq -- 'QUICK_GATE_SKIP_SHELLCHECK=1 -> shellcheck skipped' "$TMP_DIR/stdout.log"; then
  echo "[FAIL] missing explicit skip status warning" >&2
  cat "$TMP_DIR/stdout.log" >&2 || true
  exit 1
fi

if [[ -s "$TMP_DIR/stderr.log" ]]; then
  echo "[FAIL] expected empty stderr for explicit skip path" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

echo "[PASS] quick_gate preserves explicit shellcheck skip semantics in summary output"
