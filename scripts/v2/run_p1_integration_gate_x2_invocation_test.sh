#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trnm-p1-x2-gate-test.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

MARKER="$TMP_DIR/x2_called"
STUB="$TMP_DIR/x2_stub.sh"
cat >"$STUB" <<EOF
#!/usr/bin/env bash
set -euo pipefail
: > "$MARKER"
echo "[stub] x2 gate called"
EOF
chmod +x "$STUB"

P1_GATE_SDK_JS_CMD=":" \
P1_GATE_PRODUCT_LAYER_CMD=":" \
P1_GATE_SKIP_TX_ASSERT=1 \
P1_GATE_RPC_CONTRACT_CMD=":" \
P1_GATE_X2_SETTLEMENT_CMD="$STUB" \
"$ROOT/scripts/v2/run_p1_integration_gate.sh" >"$TMP_DIR/out.log" 2>&1

if [[ ! -f "$MARKER" ]]; then
  echo "[FAIL] expected x2 gate to be invoked by run_p1_integration_gate.sh"
  cat "$TMP_DIR/out.log"
  exit 1
fi

echo "[PASS] run_p1_integration_gate invokes x2 settlement contract gate"
