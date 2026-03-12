#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"

[[ -f "$SCRIPT" ]] || { echo "[FAIL] missing script: $SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-target-dirs-normalized.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TARGET_A="$TMP_DIR/zeta"
TARGET_B="$TMP_DIR/alpha"
mkdir -p "$TARGET_A" "$TARGET_B"

cat >"$TARGET_A/a.sh" <<'EOF'
#!/usr/bin/env bash
echo a
EOF
chmod +x "$TARGET_A/a.sh"

cat >"$TARGET_B/b.sh" <<'EOF'
#!/usr/bin/env bash
echo b
EOF
chmod +x "$TARGET_B/b.sh"

SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"

QUICK_GATE_SKIP_SHELLCHECK=1 \
QUICK_GATE_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" "$TARGET_A" "$TARGET_B" "$TARGET_A" >"$STDOUT_LOG" 2>"$STDERR_LOG"

python3 - <<'PY' "$SUMMARY" "$STDOUT_LOG" "$TARGET_A" "$TARGET_B"
import json, sys
summary_path, stdout_path, target_a, target_b = sys.argv[1:5]
with open(summary_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
expected_csv = f"{target_b},{target_a}"
if data.get('status') != 'warn-shellcheck-skipped':
    raise SystemExit(f"[FAIL] unexpected status: {data}")
if data.get('target_dirs_csv') != expected_csv:
    raise SystemExit(f"[FAIL] expected normalized target_dirs_csv={expected_csv!r}, got: {data}")
if int(data.get('target_dir_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected deduped target_dir_count=2, got: {data}")
if int(data.get('script_count', 0)) != 2:
    raise SystemExit(f"[FAIL] expected script_count=2, got: {data}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
if f"[quick-gate] target_dirs={target_b} {target_a}" not in stdout:
    raise SystemExit('[FAIL] missing normalized target_dirs log line')
if '[quick-gate] target_dir_count=2' not in stdout:
    raise SystemExit('[FAIL] missing deduped target_dir_count log line')
print('[PASS] quick_gate summary/logs normalize and dedupe target directory arguments deterministically')
PY

if [[ -s "$STDERR_LOG" ]]; then
  echo "[FAIL] expected empty stderr for explicit shellcheck skip path" >&2
  cat "$STDERR_LOG" >&2 || true
  exit 1
fi
