#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/m2v2_error_state_contract_gate.sh"

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] gate script is missing or not executable: $GATE" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cargo_stub="$tmpdir/cargo"

# Regression 1: cargo command succeeds but reports zero matched tests -> gate must fail-closed.
cat >"$cargo_stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "running 0 tests"
echo "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
EOF
chmod +x "$cargo_stub"

if PATH="$tmpdir:$PATH" "$GATE" >/dev/null 2>&1; then
  echo "[FAIL] M2V2 gate should fail when cargo filter matches zero tests" >&2
  exit 1
fi

# Regression 2: cargo command succeeds and reports one matched test for each invocation -> gate should pass.
cat >"$cargo_stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "running 1 test"
echo "test fake::ok ... ok"
echo "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
EOF
chmod +x "$cargo_stub"

PATH="$tmpdir:$PATH" "$GATE" >/dev/null

echo "[PASS] M2V2 error/state gate fails closed on zero-test filters and accepts non-zero matches"
