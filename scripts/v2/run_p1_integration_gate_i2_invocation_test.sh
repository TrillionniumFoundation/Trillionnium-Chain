#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trnm-p1-i2-gate-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

MARKER="$TMP_DIR/i2_called"
STUB="$TMP_DIR/i2_stub.sh"
cat >"$STUB" <<EOF
#!/usr/bin/env bash
set -euo pipefail
: > "$MARKER"
echo "[stub] i2 gate called"
EOF
chmod +x "$STUB"

P1_GATE_SDK_JS_CMD=":" \
P1_GATE_PRODUCT_LAYER_CMD=":" \
P1_GATE_SKIP_TX_ASSERT=1 \
P1_GATE_RPC_CONTRACT_CMD=":" \
P1_GATE_X2_SETTLEMENT_CMD=":" \
P1_GATE_I2_TOKEN_LIFECYCLE_CMD="$STUB" \
P1_GATE_M2_POLICY_CMD=":" \
P1_GATE_D2_INTEROP_CMD=":" \
"$ROOT/scripts/v2/run_p1_integration_gate.sh" >"$TMP_DIR/out.log" 2>&1

if [[ ! -f "$MARKER" ]]; then
  echo "[FAIL] expected i2 gate to be invoked by run_p1_integration_gate.sh"
  cat "$TMP_DIR/out.log"
  exit 1
fi

echo "[PASS] run_p1_integration_gate invokes i2 token lifecycle gate"
