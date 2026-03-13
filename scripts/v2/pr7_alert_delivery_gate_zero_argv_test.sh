#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-zero-argv.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
RUN_DIR="$TMP/run"

cat >"$MOCK_PR6" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[FAIL] PR6 gate should not run when delivery command resolves to zero argv entries" >&2
exit 99
EOF
chmod +x "$MOCK_PR6"

set +e
RUN_DIR="$RUN_DIR" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="''" \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/out.log" 2>&1
rc=$?
set -e

if [[ $rc -ne 2 ]]; then
  echo "[FAIL] expected rc=2 for empty-command-token PR7_DELIVERY_CMD, got rc=$rc"
  cat "$TMP/out.log"
  exit 1
fi

if ! grep -q "PR7_DELIVERY_CMD resolved to an empty command token" "$TMP/out.log"; then
  echo "[FAIL] expected empty-command-token validation message"
  cat "$TMP/out.log"
  exit 1
fi

if grep -q "PR6 gate should not run" "$TMP/out.log"; then
  echo "[FAIL] execution continued past zero-argv delivery command validation"
  cat "$TMP/out.log"
  exit 1
fi

echo "[OK] pr7 gate rejects PR7_DELIVERY_CMD values that shell-split to an empty command token"
