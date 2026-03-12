#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-manifest-hash.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TARGET_DIR="$TMP_DIR/scripts"
mkdir -p "$TARGET_DIR"
TARGET_SCRIPT="$TARGET_DIR/sample.sh"
SUMMARY_A="$TMP_DIR/summary-a.json"
SUMMARY_B="$TMP_DIR/summary-b.json"

cat >"$TARGET_SCRIPT" <<'EOF'
#!/usr/bin/env bash
echo first
EOF
chmod +x "$TARGET_SCRIPT"

QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$SUMMARY_A" bash "$SCRIPT" "$TARGET_DIR" >"$TMP_DIR/run-a.log"

cat >"$TARGET_SCRIPT" <<'EOF'
#!/usr/bin/env bash
echo second
EOF
chmod +x "$TARGET_SCRIPT"

QUICK_GATE_SKIP_SHELLCHECK=1 QUICK_GATE_SUMMARY_PATH="$SUMMARY_B" bash "$SCRIPT" "$TARGET_DIR" >"$TMP_DIR/run-b.log"

python3 - <<'PY' "$SUMMARY_A" "$SUMMARY_B"
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fa:
    a = json.load(fa)
with open(sys.argv[2], 'r', encoding='utf-8') as fb:
    b = json.load(fb)
if a['script_count'] != 1 or b['script_count'] != 1:
    raise SystemExit(f"unexpected script counts: {a['script_count']} {b['script_count']}")
if a['file_manifest_sha256'] == b['file_manifest_sha256']:
    raise SystemExit('manifest hash did not change after script content changed')
print('ok')
PY

echo "[PASS] quick gate manifest hash tracks script content drift"
