#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-escape.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WEIRD_DIR="$TMP_DIR/dir-with-\"quote"
mkdir -p "$WEIRD_DIR"
cat >"$WEIRD_DIR/sample.sh" <<'EOF'
#!/usr/bin/env bash
echo ok
EOF
chmod +x "$WEIRD_DIR/sample.sh"

SUMMARY="$TMP_DIR/summary.json"
QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$SUMMARY" bash "$SCRIPT" "$WEIRD_DIR" >/dev/null

python3 - <<'PY' "$SUMMARY" 'dir-with-"quote'
import json, sys
summary = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
needle = sys.argv[2]
csv = summary.get('target_dirs_csv', '')
assert needle in csv, (needle, csv)
assert summary.get('status') == 'ok', summary
print('ok')
PY

echo "[PASS] quick_gate summary JSON escaping test"