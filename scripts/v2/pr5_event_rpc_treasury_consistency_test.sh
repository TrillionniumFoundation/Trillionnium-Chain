#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

EVENT_LOG="$TMP_DIR/event.log"
PR5_SUMMARY="$TMP_DIR/summary.txt"
RPC_OK="$TMP_DIR/rpc-ok.json"
RPC_BALANCE_SPENT_OK="$TMP_DIR/rpc-balance-spent-ok.json"
RPC_BAD="$TMP_DIR/rpc-bad.json"
RPC_KNOWN_ANOMALY_OK="$TMP_DIR/rpc-known-anomaly-ok.json"
RPC_UNKNOWN_ANOMALY_BAD="$TMP_DIR/rpc-unknown-anomaly-bad.json"

cat >"$EVENT_LOG" <<'EOF'
[event] event_type=challenge task_id=1 tx_hash=0x1 treasury_delta=0 challenger_delta=-10 bond_disposition=posted
[event] event_type=resolve task_id=1 tx_hash=0x2 treasury_delta=0 challenger_delta=10 bond_disposition=refunded
[event] event_type=challenge task_id=2 tx_hash=0x3 treasury_delta=0 challenger_delta=-5 bond_disposition=posted
[event] event_type=resolve task_id=2 tx_hash=0x4 treasury_delta=0 challenger_delta=0 bond_disposition=forfeited
EOF

cat >"$PR5_SUMMARY" <<'EOF'
status=PASS
record_count=4
conservation.gap=0
EOF

cat >"$RPC_OK" <<'EOF'
{"current_forfeits_balance":5,"cumulative_forfeited":5,"events":[{"event_type":"challenge"},{"event_type":"resolve"},{"event_type":"challenge"},{"event_type":"resolve"}]}
EOF

cat >"$RPC_BALANCE_SPENT_OK" <<'EOF'
{"current_forfeits_balance":0,"cumulative_forfeited":5,"events":[{"event_type":"challenge"},{"event_type":"resolve"},{"event_type":"challenge"},{"event_type":"resolve"}]}
EOF

cat >"$RPC_BAD" <<'EOF'
{"current_forfeits_balance":0,"cumulative_forfeited":0,"events":[{"event_type":"challenge"}]}
EOF

cat >"$RPC_KNOWN_ANOMALY_OK" <<'EOF'
{"current_forfeits_balance":5,"cumulative_forfeited":5,"anomaly_count":1,"anomalies":[{"code":"duplicate_event_replay"}],"events":[{"event_type":"challenge"},{"event_type":"resolve"},{"event_type":"challenge"},{"event_type":"resolve"}]}
EOF

cat >"$RPC_UNKNOWN_ANOMALY_BAD" <<'EOF'
{"current_forfeits_balance":5,"cumulative_forfeited":5,"anomaly_count":1,"anomalies":[{"code":"unexpected_semantic_drift"}],"events":[{"event_type":"challenge"},{"event_type":"resolve"},{"event_type":"challenge"},{"event_type":"resolve"}]}
EOF

python3 "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency.py" \
  --event-log "$EVENT_LOG" \
  --pr5-summary "$PR5_SUMMARY" \
  --rpc-treasury-json "$RPC_OK" \
  --report "$TMP_DIR/out-ok.txt" >/dev/null

if ! grep -q '^status=PASS$' "$TMP_DIR/out-ok.txt"; then
  echo "[TEST][FAIL] expected PASS for consistent triad"
  cat "$TMP_DIR/out-ok.txt"
  exit 1
fi

python3 "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency.py" \
  --event-log "$EVENT_LOG" \
  --pr5-summary "$PR5_SUMMARY" \
  --rpc-treasury-json "$RPC_BALANCE_SPENT_OK" \
  --report "$TMP_DIR/out-balance-spent-ok.txt" >/dev/null

if ! grep -q '^status=PASS$' "$TMP_DIR/out-balance-spent-ok.txt"; then
  echo "[TEST][FAIL] expected PASS when balance is spent but cumulative_forfeited is sufficient"
  cat "$TMP_DIR/out-balance-spent-ok.txt"
  exit 1
fi

python3 "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency.py" \
  --event-log "$EVENT_LOG" \
  --pr5-summary "$PR5_SUMMARY" \
  --rpc-treasury-json "$RPC_KNOWN_ANOMALY_OK" \
  --report "$TMP_DIR/out-known-anomaly-ok.txt" >/dev/null

if ! grep -q '^status=PASS$' "$TMP_DIR/out-known-anomaly-ok.txt"; then
  echo "[TEST][FAIL] expected PASS when rpc anomaly only has known code"
  cat "$TMP_DIR/out-known-anomaly-ok.txt"
  exit 1
fi

set +e
python3 "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency.py" \
  --event-log "$EVENT_LOG" \
  --pr5-summary "$PR5_SUMMARY" \
  --rpc-treasury-json "$RPC_UNKNOWN_ANOMALY_BAD" \
  --report "$TMP_DIR/out-unknown-anomaly-bad.txt" >/dev/null
rc_unknown=$?
set -e
if [[ "$rc_unknown" -eq 0 ]]; then
  echo "[TEST][FAIL] expected FAIL for unknown rpc anomaly code"
  cat "$TMP_DIR/out-unknown-anomaly-bad.txt"
  exit 1
fi

if ! grep -q '^status=FAIL$' "$TMP_DIR/out-unknown-anomaly-bad.txt"; then
  echo "[TEST][FAIL] expected FAIL status for unknown anomaly"
  cat "$TMP_DIR/out-unknown-anomaly-bad.txt"
  exit 1
fi

set +e
python3 "$ROOT/scripts/v2/pr5_event_rpc_treasury_consistency.py" \
  --event-log "$EVENT_LOG" \
  --pr5-summary "$PR5_SUMMARY" \
  --rpc-treasury-json "$RPC_BAD" \
  --report "$TMP_DIR/out-bad.txt" >/dev/null
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "[TEST][FAIL] expected FAIL for inconsistent triad"
  cat "$TMP_DIR/out-bad.txt"
  exit 1
fi

if ! grep -q '^status=FAIL$' "$TMP_DIR/out-bad.txt"; then
  echo "[TEST][FAIL] expected FAIL status"
  cat "$TMP_DIR/out-bad.txt"
  exit 1
fi

echo "[TEST][PASS] pr5 event/rpc/treasury triad consistency regression covered"
