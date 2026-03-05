#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d /tmp/trnm-pr7-gate-concurrency.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6_SLEEP="$TMP/mock_pr6_sleep.sh"
cat >"$MOCK_PR6_SLEEP" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${RUN_DIR:?}"
mkdir -p "$RUN_DIR"
sleep 2
cat >"$RUN_DIR/summary.txt" <<'EOR'
status=WARN
alert_level=WARN
alert_code=PR6_ALERT_RULES
EOR
EOS
chmod +x "$MOCK_PR6_SLEEP"

MOCK_PR6_FAST="$TMP/mock_pr6_fast.sh"
cat >"$MOCK_PR6_FAST" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${RUN_DIR:?}"
mkdir -p "$RUN_DIR"
cat >"$RUN_DIR/summary.txt" <<'EOR'
status=WARN
alert_level=WARN
alert_code=PR6_ALERT_RULES
EOR
EOS
chmod +x "$MOCK_PR6_FAST"

MOCK_PR7_OK="$TMP/mock_pr7_ok.sh"
cat >"$MOCK_PR7_OK" <<'EOS'
#!/usr/bin/env bash
exit 0
EOS
chmod +x "$MOCK_PR7_OK"

LOCK_DIR="$TMP/.pr7-lock"

# Case 1: concurrent run should not overlap; second run times out on lock.
RUN_DIR="$TMP/run-a" PR7_GATE_LOCK_DIR="$LOCK_DIR" PR7_GATE_LOCK_WAIT_SECONDS=10 PR7_GATE_LOCK_JITTER_MIN_MS=120 PR7_GATE_LOCK_JITTER_MAX_MS=120 PR6_GATE_CMD="$MOCK_PR6_SLEEP" PR7_DELIVERY_CMD="$MOCK_PR7_OK" \
  "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/run-a.out" 2>&1 &
pid1=$!

sleep 0.2
set +e
RUN_DIR="$TMP/run-b" PR7_GATE_LOCK_DIR="$LOCK_DIR" PR7_GATE_LOCK_WAIT_SECONDS=1 PR7_GATE_LOCK_JITTER_MIN_MS=120 PR7_GATE_LOCK_JITTER_MAX_MS=120 PR6_GATE_CMD="$MOCK_PR6_FAST" PR7_DELIVERY_CMD="$MOCK_PR7_OK" \
  "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/run-b.out" 2>&1
rc2=$?
set -e
wait "$pid1"

if [[ "$rc2" -ne 5 ]]; then
  echo "[FAIL] expected second concurrent run to exit rc=5 on lock timeout, got rc=$rc2"
  cat "$TMP/run-b.out"
  exit 1
fi
if ! grep -q "lock timeout" "$TMP/run-b.out"; then
  echo "[FAIL] missing lock-timeout marker"
  cat "$TMP/run-b.out"
  exit 1
fi

# Case 2: default RUN_DIR should be collision-resistant.
PR6_GATE_CMD="$MOCK_PR6_FAST" PR7_DELIVERY_CMD="$MOCK_PR7_OK" PR7_GATE_LOCK_DIR="$TMP/.pr7-lock-2" "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/auto1.out" 2>&1
PR6_GATE_CMD="$MOCK_PR6_FAST" PR7_DELIVERY_CMD="$MOCK_PR7_OK" PR7_GATE_LOCK_DIR="$TMP/.pr7-lock-3" "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$TMP/auto2.out" 2>&1

status1="$(sed -n 's/.*status_file=\([^ ]*\).*/\1/p' "$TMP/auto1.out" | head -n1)"
status2="$(sed -n 's/.*status_file=\([^ ]*\).*/\1/p' "$TMP/auto2.out" | head -n1)"
if [[ -z "$status1" || -z "$status2" ]]; then
  echo "[FAIL] unable to parse status_file path"
  cat "$TMP/auto1.out"
  cat "$TMP/auto2.out"
  exit 1
fi
if [[ "$status1" == "$status2" ]]; then
  echo "[FAIL] default RUN_DIR collision: status_file paths are identical"
  echo "status1=$status1"
  echo "status2=$status2"
  exit 1
fi

echo "[OK] pr7 non-gate concurrency guard + RUN_DIR uniqueness regression passed"
