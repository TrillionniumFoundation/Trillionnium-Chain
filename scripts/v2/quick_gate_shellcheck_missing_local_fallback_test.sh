#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-shellcheck-missing-fallback.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TARGET_DIR="$TMP_DIR/target"
mkdir -p "$TARGET_DIR"
cat >"$TARGET_DIR/sample.sh" <<'EOF'
#!/usr/bin/env bash
echo ok
EOF
chmod +x "$TARGET_DIR/sample.sh"

FAKE_BIN="$TMP_DIR/fake-bin"
mkdir -p "$FAKE_BIN"
for required_tool in awk bash cat date dirname find mkdir sha256sum sort; do
  ln -s "$(command -v "$required_tool")" "$FAKE_BIN/$required_tool"
done

SUMMARY="$TMP_DIR/summary.json"
BASH_BIN="$(command -v bash)"
PATH="$FAKE_BIN" CI=false QUICK_GATE_SUMMARY_PATH="$SUMMARY" "$BASH_BIN" "$SCRIPT" "$TARGET_DIR" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"

python3 - <<'PY' "$SUMMARY"
import json, sys
summary = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
if summary.get('shellcheck_requested') != 0:
    raise SystemExit(f"expected shellcheck_requested=0, got {summary.get('shellcheck_requested')}")
if summary.get('skip_shellcheck') != 1:
    raise SystemExit(f"expected skip_shellcheck=1 after fallback, got {summary.get('skip_shellcheck')}")
if summary.get('shellcheck_fallback_reason') != 'shellcheck-missing-local-fallback':
    raise SystemExit(summary)
if summary.get('shellcheck_status') != 'shellcheck-missing-local-fallback':
    raise SystemExit(summary)
if summary.get('status') != 'warn-shellcheck-unavailable-local-fallback':
    raise SystemExit(summary)
print('ok')
PY

if ! grep -Fq -- 'shellcheck not found in PATH -> falling back to bash -n only for non-CI local run' "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing shellcheck fallback warning" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if ! grep -Fq -- 'shellcheck unavailable -> shellcheck-missing-local-fallback' "$TMP_DIR/stdout.log"; then
  echo "[FAIL] missing explicit shellcheck fallback status warning" >&2
  cat "$TMP_DIR/stdout.log" >&2 || true
  exit 1
fi

echo "[PASS] quick_gate distinguishes local shellcheck fallback from explicit skip"
