#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-pr7-gate-rc-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
MOCK_PR7="$TMP/mock_pr7.sh"
RUN_DIR="$TMP/run"

cat >"$MOCK_PR6" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${RUN_DIR:?}"
cat >"${RUN_DIR}/summary.txt" <<'EOR'
status=PASS
alert_code=NONE
alert_message=ok
generated_at_utc=2026-02-24T00:00:00+00:00
EOR
exit 0
EOF
chmod +x "$MOCK_PR6"

cat >"$MOCK_PR7" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 42
EOF
chmod +x "$MOCK_PR7"

set +e
RUN_DIR="$RUN_DIR" PR6_GATE_CMD="$MOCK_PR6" PR7_DELIVERY_CMD="$MOCK_PR7" PR7_DELIVERY_FAIL_MODE=ignore \
  "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/ignore.out" 2>&1
rc_ignore=$?
set -e

if [[ $rc_ignore -ne 0 ]]; then
  echo "[FAIL] ignore mode should preserve pr6_rc=0, got rc=$rc_ignore"
  cat "$TMP/ignore.out"
  exit 1
fi
if ! grep -q "pr7_rc=42" "$RUN_DIR/pr7-delivery-status.env"; then
  echo "[FAIL] status file should keep pr7_rc"
  cat "$RUN_DIR/pr7-delivery-status.env"
  exit 1
fi
if ! grep -q "final_rc=0" "$RUN_DIR/pr7-delivery-status.env"; then
  echo "[FAIL] ignore mode should record final_rc=0"
  cat "$RUN_DIR/pr7-delivery-status.env"
  exit 1
fi

set +e
RUN_DIR="$RUN_DIR" PR6_GATE_CMD="$MOCK_PR6" PR7_DELIVERY_CMD="$MOCK_PR7" PR7_DELIVERY_FAIL_MODE=warn \
  "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/warn.out" 2>&1
rc_warn=$?
set -e

if [[ $rc_warn -ne 0 ]]; then
  echo "[FAIL] warn mode should preserve pr6_rc=0, got rc=$rc_warn"
  cat "$TMP/warn.out"
  exit 1
fi
if ! grep -q "\[PR7\]\[WARN\] delivery failed with rc=42 (mode=warn, preserving pr6 rc=0)" "$TMP/warn.out"; then
  echo "[FAIL] warn mode should emit delivery warning"
  cat "$TMP/warn.out"
  exit 1
fi
if ! grep -q "fail_mode=warn" "$RUN_DIR/pr7-delivery-status.env"; then
  echo "[FAIL] status file should record fail_mode=warn"
  cat "$RUN_DIR/pr7-delivery-status.env"
  exit 1
fi
if ! grep -q "final_rc=0" "$RUN_DIR/pr7-delivery-status.env"; then
  echo "[FAIL] warn mode should preserve final_rc=0"
  cat "$RUN_DIR/pr7-delivery-status.env"
  exit 1
fi

set +e
RUN_DIR="$RUN_DIR" PR6_GATE_CMD="$MOCK_PR6" PR7_DELIVERY_CMD="$MOCK_PR7" PR7_DELIVERY_FAIL_MODE=escalate \
  "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/escalate.out" 2>&1
rc_escalate=$?
set -e

if [[ $rc_escalate -ne 4 ]]; then
  echo "[FAIL] escalate mode should return rc=4 on delivery failure, got rc=$rc_escalate"
  cat "$TMP/escalate.out"
  exit 1
fi
if ! grep -q "final_rc=4" "$RUN_DIR/pr7-delivery-status.env"; then
  echo "[FAIL] status file should record final_rc=4"
  cat "$RUN_DIR/pr7-delivery-status.env"
  exit 1
fi

echo "[OK] pr7 gate preserves pr7_rc observability across ignore/warn/escalate modes"
