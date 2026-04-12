#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_SCRIPT="$ROOT/scripts/check_contracts_workspace_smoke.sh"

[[ -f "$SOURCE_SCRIPT" ]] || { echo "[FAIL] missing script: $SOURCE_SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/contracts-workspace-smoke-repo-root-target-dir.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

TEST_ROOT="$TMP_DIR/repo"
mkdir -p "$TEST_ROOT/scripts" "$TEST_ROOT/contracts"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
cp "$SOURCE_SCRIPT" "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
chmod +x "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
cat >"$TEST_ROOT/contracts/Cargo.toml" <<'EOF'
[workspace]
members = []
EOF

BAD_TARGET_DIR="$TMP_DIR/outside-target/contracts-workspace-smoke"
set +e
(
  cd "$TEST_ROOT"
  CARGO_TARGET_DIR="$BAD_TARGET_DIR" /bin/bash "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
) >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] contracts workspace smoke accepted cargo target dir outside repo root" >&2
  exit 1
fi

if [[ "$rc" -ne 1 ]]; then
  echo "[FAIL] expected exit code 1 for outside-repo cargo target dir, got: $rc" >&2
  exit 1
fi

expected="[FAIL] CARGO_TARGET_DIR must stay under repo root: $BAD_TARGET_DIR -> $(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$BAD_TARGET_DIR")"
if ! grep -Fq -- "$expected" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] outside-repo cargo target dir guard message not found" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

if [[ -e "$BAD_TARGET_DIR" ]]; then
  echo "[FAIL] outside-repo cargo target dir should not be created: $BAD_TARGET_DIR" >&2
  exit 1
fi

echo "[PASS] contracts workspace smoke rejects cargo target dirs outside repo root"
