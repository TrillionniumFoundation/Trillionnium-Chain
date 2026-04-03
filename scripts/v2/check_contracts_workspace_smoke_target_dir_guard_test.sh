#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_SCRIPT="$ROOT/scripts/check_contracts_workspace_smoke.sh"

[[ -f "$SOURCE_SCRIPT" ]] || { echo "[FAIL] missing script: $SOURCE_SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/contracts-workspace-smoke-target-dir.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

TEST_ROOT="$TMP_DIR/repo"
mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/contracts-rust"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd)"
cp "$SOURCE_SCRIPT" "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
chmod +x "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
cat >"$TEST_ROOT/contracts-rust/Cargo.toml" <<'EOF'
[workspace]
members = []
EOF

FAKE_BIN_DIR="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN_DIR"
cat >"$FAKE_BIN_DIR/fake-cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${CARGO_TARGET_DIR:-}" >> "${FAKE_CARGO_LOG:?}"
subcommand="${1:-}"
case "$subcommand" in
  metadata)
    printf '{"target_directory":"%s","workspace_root":"%s/contracts-rust"}\n' "${CARGO_TARGET_DIR:-}" "${PWD}"
    exit 0
    ;;
  check|test)
    exit 0
    ;;
  *)
    echo "unexpected cargo subcommand: $subcommand" >&2
    exit 97
    ;;
esac
EOF
chmod +x "$FAKE_BIN_DIR/fake-cargo"

FAKE_CARGO_LOG="$TMP_DIR/cargo-target-dirs.log"
set +e
PATH="$FAKE_BIN_DIR:/usr/bin:/bin:/usr/sbin:/sbin" CARGO_BIN="fake-cargo" FAKE_CARGO_LOG="$FAKE_CARGO_LOG" /bin/bash "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
  echo "[FAIL] smoke script exited non-zero under fake cargo: $rc" >&2
  cat "$TMP_DIR/stdout.log" >&2 || true
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

EXPECTED_TARGET_DIR="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$TEST_ROOT/target/contracts-rust-workspace-smoke")"
if [[ ! -d "$EXPECTED_TARGET_DIR" ]]; then
  echo "[FAIL] expected target dir missing: $EXPECTED_TARGET_DIR" >&2
  exit 1
fi

if [[ ! -f "$FAKE_CARGO_LOG" ]]; then
  echo "[FAIL] fake cargo log missing" >&2
  exit 1
fi

line_count="$(wc -l < "$FAKE_CARGO_LOG" | tr -d ' ')"
if [[ "$line_count" -ne 3 ]]; then
  echo "[FAIL] expected 3 cargo invocations, got: $line_count" >&2
  cat "$FAKE_CARGO_LOG" >&2
  exit 1
fi

while IFS= read -r line; do
  if [[ "$line" != "$EXPECTED_TARGET_DIR" ]]; then
    echo "[FAIL] cargo used unexpected target dir: $line" >&2
    exit 1
  fi
done < "$FAKE_CARGO_LOG"

if [[ -e "$TEST_ROOT/contracts-rust/target" ]]; then
  echo "[FAIL] contracts-rust/target should not be created by smoke script" >&2
  exit 1
fi

echo "[PASS] contracts workspace smoke keeps cargo artifacts outside contracts-rust/target"
