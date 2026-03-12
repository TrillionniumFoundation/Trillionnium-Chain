#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-target-dir-normalization.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

DIR_B="$TMP_DIR/b-dir"
DIR_A="$TMP_DIR/a-dir"
mkdir -p "$DIR_B" "$DIR_A"

cat >"$DIR_B/b.sh" <<'EOF'
#!/usr/bin/env bash
echo b
EOF
chmod +x "$DIR_B/b.sh"

cat >"$DIR_A/a.sh" <<'EOF'
#!/usr/bin/env bash
echo a
EOF
chmod +x "$DIR_A/a.sh"

SUMMARY="$TMP_DIR/summary.json"
STDOUT_LOG="$TMP_DIR/stdout.log"

QUICK_GATE_SKIP_SHELLCHECK=1 \
QUICK_GATE_SUMMARY_PATH="$SUMMARY" \
  bash "$SCRIPT" "$DIR_B" "$DIR_A" "$DIR_B" >"$STDOUT_LOG"

python3 - <<'PY' "$SUMMARY" "$STDOUT_LOG" "$DIR_A" "$DIR_B"
import json, sys
summary_path, stdout_path, dir_a, dir_b = sys.argv[1:5]
summary = json.load(open(summary_path, 'r', encoding='utf-8'))
expected_csv = f"{dir_a},{dir_b}"
if summary.get('target_dir_count') != 2:
    raise SystemExit(f"expected target_dir_count=2, got {summary.get('target_dir_count')}")
if summary.get('target_dirs_csv') != expected_csv:
    raise SystemExit(
        f"expected target_dirs_csv={expected_csv!r}, got {summary.get('target_dirs_csv')!r}"
    )
if summary.get('script_count') != 2:
    raise SystemExit(f"expected script_count=2, got {summary.get('script_count')}")
stdout = open(stdout_path, 'r', encoding='utf-8').read()
if f"[quick-gate] target_dirs={dir_a} {dir_b}" not in stdout:
    raise SystemExit('missing deterministic sorted target_dirs log line')
if '[quick-gate] target_dir_count=2' not in stdout:
    raise SystemExit('missing deduplicated target_dir_count log line')
print('ok')
PY

echo "[PASS] quick gate normalizes and deduplicates target dirs deterministically"
