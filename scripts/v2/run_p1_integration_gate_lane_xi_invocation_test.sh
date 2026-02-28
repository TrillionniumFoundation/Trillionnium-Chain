#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trnm-p1-lanexi-gate-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

X2_MARKER="$TMP_DIR/x2_called"
I2_MARKER="$TMP_DIR/i2_called"
M2_MARKER="$TMP_DIR/m2_called"

make_stub() {
  local marker="$1"
  local label="$2"
  local path="$3"
  cat >"$path" <<EOF
#!/usr/bin/env bash
set -euo pipefail
: > "$marker"
echo "[stub] $label gate called"
EOF
  chmod +x "$path"
}

X2_STUB="$TMP_DIR/x2_stub.sh"
I2_STUB="$TMP_DIR/i2_stub.sh"
M2_STUB="$TMP_DIR/m2_stub.sh"
make_stub "$X2_MARKER" "x2" "$X2_STUB"
make_stub "$I2_MARKER" "i2" "$I2_STUB"
make_stub "$M2_MARKER" "m2" "$M2_STUB"

P1_GATE_SDK_JS_CMD=":" \
P1_GATE_PRODUCT_LAYER_CMD=":" \
P1_GATE_SKIP_TX_ASSERT=1 \
P1_GATE_RPC_CONTRACT_CMD=":" \
P1_GATE_X2_SETTLEMENT_CMD="$X2_STUB" \
P1_GATE_I2_TOKEN_LIFECYCLE_CMD="$I2_STUB" \
P1_GATE_M2_POLICY_CMD="$M2_STUB" \
"$ROOT/scripts/v2/run_p1_integration_gate.sh" >"$TMP_DIR/out.log" 2>&1

for marker in "$X2_MARKER" "$I2_MARKER" "$M2_MARKER"; do
  if [[ ! -f "$marker" ]]; then
    echo "[FAIL] expected all lane XI gates (x2/i2/m2) to be invoked by run_p1_integration_gate.sh"
    cat "$TMP_DIR/out.log"
    exit 1
  fi
done

echo "[PASS] run_p1_integration_gate invokes lane XI gate chain (x2/i2/m2)"
