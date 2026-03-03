#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trnm-p1-lanexi-gate-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

X2_MARKER="$TMP_DIR/x2_called"
I2_MARKER="$TMP_DIR/i2_called"
M2_MARKER="$TMP_DIR/m2_called"
V1_MARKER="$TMP_DIR/v1_called"
MV2_MARKER="$TMP_DIR/mv2_called"
D2_MARKER="$TMP_DIR/d2_called"

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
V1_STUB="$TMP_DIR/v1_stub.sh"
MV2_STUB="$TMP_DIR/mv2_stub.sh"
D2_STUB="$TMP_DIR/d2_stub.sh"
make_stub "$X2_MARKER" "x2" "$X2_STUB"
make_stub "$I2_MARKER" "i2" "$I2_STUB"
make_stub "$M2_MARKER" "m2" "$M2_STUB"
make_stub "$V1_MARKER" "v1" "$V1_STUB"
make_stub "$MV2_MARKER" "mv2" "$MV2_STUB"
make_stub "$D2_MARKER" "d2" "$D2_STUB"

P1_GATE_SDK_JS_CMD=":" \
P1_GATE_PRODUCT_LAYER_CMD=":" \
P1_GATE_SKIP_TX_ASSERT=1 \
P1_GATE_RPC_CONTRACT_CMD=":" \
P1_GATE_X2_SETTLEMENT_CMD="$X2_STUB" \
P1_GATE_I2_TOKEN_LIFECYCLE_CMD="$I2_STUB" \
P1_GATE_M2_POLICY_CMD="$M2_STUB" \
P1_GATE_V1_PROOF_REGISTRY_CMD="$V1_STUB" \
P1_GATE_MV2_RECEIPT_CONTRACT_CMD="$MV2_STUB" \
P1_GATE_D2_INTEROP_CMD="$D2_STUB" \
"$ROOT/scripts/v2/run_p1_integration_gate.sh" >"$TMP_DIR/out.log" 2>&1

for marker in "$X2_MARKER" "$I2_MARKER" "$M2_MARKER" "$V1_MARKER" "$MV2_MARKER" "$D2_MARKER"; do
  if [[ ! -f "$marker" ]]; then
    echo "[FAIL] expected all lane XI/MV2/V1/D2 gates (x2/i2/m2/v1/mv2/d2) to be invoked by run_p1_integration_gate.sh"
    cat "$TMP_DIR/out.log"
    exit 1
  fi
done

echo "[PASS] run_p1_integration_gate invokes lane XI/MV2/V1/D2 gate chain (x2/i2/m2/v1/mv2/d2)"
