#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-pr7-gate-invalid-lock-config.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
MOCK_PR7="$TMP/mock_pr7.sh"

cat >"$MOCK_PR6" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${RUN_DIR:?}"
cat >"${RUN_DIR}/summary.txt" <<'EOR'
status=PASS
alert_code=NONE
alert_message=ok
generated_at_utc=2026-03-12T00:00:00Z
EOR
exit 0
EOF
chmod +x "$MOCK_PR6"

cat >"$MOCK_PR7" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF
chmod +x "$MOCK_PR7"

set +e
RUN_DIR="$TMP/run-a" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="$MOCK_PR7" \
PR7_GATE_LOCK_JITTER_MIN_MS=250 \
PR7_GATE_LOCK_JITTER_MAX_MS=100 \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/out-a.log" 2>&1
rc_a=$?
set -e

if [[ $rc_a -ne 2 ]]; then
  echo "[FAIL] expected rc=2 for jitter max<min, got rc=$rc_a"
  cat "$TMP/out-a.log"
  exit 1
fi
if ! grep -q "PR7_GATE_LOCK_JITTER_MAX_MS must be >= PR7_GATE_LOCK_JITTER_MIN_MS" "$TMP/out-a.log"; then
  echo "[FAIL] missing jitter validation error"
  cat "$TMP/out-a.log"
  exit 1
fi

set +e
RUN_DIR="$TMP/run-b" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="$MOCK_PR7" \
PR7_GATE_LOCK_WAIT_SECONDS=abc \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/out-b.log" 2>&1
rc_b=$?
set -e

if [[ $rc_b -ne 2 ]]; then
  echo "[FAIL] expected rc=2 for non-integer lock wait, got rc=$rc_b"
  cat "$TMP/out-b.log"
  exit 1
fi
if ! grep -q "invalid PR7_GATE_LOCK_WAIT_SECONDS='abc'" "$TMP/out-b.log"; then
  echo "[FAIL] missing non-integer lock wait validation error"
  cat "$TMP/out-b.log"
  exit 1
fi

echo "[OK] pr7 gate rejects invalid lock timing config before execution"
