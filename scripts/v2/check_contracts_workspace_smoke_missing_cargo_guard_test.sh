#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_SCRIPT="$ROOT/scripts/check_contracts_workspace_smoke.sh"

[[ -f "$SOURCE_SCRIPT" ]] || { echo "[FAIL] missing script: $SOURCE_SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/contracts-workspace-smoke-missing-cargo.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TEST_ROOT="$TMP_DIR/repo"
mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/contracts-rust"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd)"
cp "$SOURCE_SCRIPT" "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
chmod +x "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
cat >"$TEST_ROOT/contracts-rust/Cargo.toml" <<'EOF'
[workspace]
members = []
EOF

set +e
CARGO_BIN="missing-cargo" PATH="/usr/bin:/bin:/usr/sbin:/sbin" /bin/bash "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh" >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] contracts workspace smoke accepted missing cargo" >&2
  exit 1
fi

if [[ "$rc" -ne 1 ]]; then
  echo "[FAIL] expected exit code 1 for missing cargo, got: $rc" >&2
  exit 1
fi

expected="[FAIL] cargo binary not found: missing-cargo"
if ! grep -Fq -- "$expected" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] missing cargo guard message not found" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

echo "[PASS] contracts workspace smoke rejects missing cargo binary"
