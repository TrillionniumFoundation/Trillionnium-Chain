#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_SCRIPT="$ROOT/scripts/check_contracts_workspace_smoke.sh"

[[ -f "$SOURCE_SCRIPT" ]] || { echo "[FAIL] missing script: $SOURCE_SCRIPT" >&2; exit 1; }

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/contracts-workspace-smoke-exact-repo-root-target-dir.XXXXXX")"
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

FAKE_BIN_DIR="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN_DIR"
cat >"$FAKE_BIN_DIR/fake-cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "fake cargo should not be invoked for repo-root target dir" >&2
exit 97
EOF
chmod +x "$FAKE_BIN_DIR/fake-cargo"

set +e
(
  cd "$TEST_ROOT"
  PATH="$FAKE_BIN_DIR:/usr/bin:/bin:/usr/sbin:/sbin" CARGO_BIN="fake-cargo" CARGO_TARGET_DIR="." /bin/bash "$TEST_ROOT/scripts/check_contracts_workspace_smoke.sh"
) >"$TMP_DIR/stdout.log" 2>"$TMP_DIR/stderr.log"
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] contracts workspace smoke accepted repo root as cargo target dir" >&2
  exit 1
fi

if [[ "$rc" -ne 1 ]]; then
  echo "[FAIL] expected exit code 1 for repo-root cargo target dir, got: $rc" >&2
  cat "$TMP_DIR/stderr.log" >&2 || true
  exit 1
fi

expected="[FAIL] CARGO_TARGET_DIR must not be repo root: . -> $TEST_ROOT"
if ! grep -Fq -- "$expected" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] exact repo-root cargo target dir guard message not found" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

if grep -Fq -- "fake cargo should not be invoked" "$TMP_DIR/stderr.log"; then
  echo "[FAIL] fake cargo was invoked before repo-root target dir guard" >&2
  cat "$TMP_DIR/stderr.log" >&2
  exit 1
fi

echo "[PASS] contracts workspace smoke rejects repo root as cargo target dir"
