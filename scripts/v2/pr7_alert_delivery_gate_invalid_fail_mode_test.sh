#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-pr7-gate-invalid-fail-mode.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
MOCK_PR7="$TMP/mock_pr7.sh"
RUN_DIR="$TMP/run"

cat >"$MOCK_PR6" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[FAIL] PR6 gate should not run when fail mode is invalid" >&2
exit 99
EOF
chmod +x "$MOCK_PR6"

cat >"$MOCK_PR7" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[FAIL] PR7 delivery should not run when fail mode is invalid" >&2
exit 99
EOF
chmod +x "$MOCK_PR7"

set +e
RUN_DIR="$RUN_DIR" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="$MOCK_PR7" \
PR7_DELIVERY_FAIL_MODE=panic \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/out.log" 2>&1
rc=$?
set -e

if [[ $rc -ne 2 ]]; then
  echo "[FAIL] expected rc=2 for invalid PR7_DELIVERY_FAIL_MODE, got rc=$rc"
  cat "$TMP/out.log"
  exit 1
fi

if ! grep -q "invalid PR7_DELIVERY_FAIL_MODE='panic'" "$TMP/out.log"; then
  echo "[FAIL] expected invalid fail-mode message"
  cat "$TMP/out.log"
  exit 1
fi

if grep -q "PR6 gate should not run" "$TMP/out.log" || grep -q "PR7 delivery should not run" "$TMP/out.log"; then
  echo "[FAIL] execution continued past fail-mode validation"
  cat "$TMP/out.log"
  exit 1
fi

echo "[OK] pr7 gate rejects invalid PR7_DELIVERY_FAIL_MODE before execution"
