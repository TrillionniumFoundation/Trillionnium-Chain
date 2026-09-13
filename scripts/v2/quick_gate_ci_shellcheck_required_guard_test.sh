#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/quick_gate_shell.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/quick-gate-ci-shellcheck-required-guard.XXXXXX")"
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
BASH_BIN="$(command -v bash)"
ln -s "$(command -v date)" "$FAKE_BIN/date"
ln -s "$(command -v dirname)" "$FAKE_BIN/dirname"

set +e
PATH="$FAKE_BIN" CI=true "$BASH_BIN" "$SCRIPT" "$TARGET_DIR" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected exit code 2 when shellcheck is missing under CI, got: $rc" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

if ! grep -Fq -- 'shellcheck not found in PATH under CI' "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing fail-closed CI shellcheck guard message" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

echo "[PASS] quick_gate fails closed when shellcheck is missing under CI"
