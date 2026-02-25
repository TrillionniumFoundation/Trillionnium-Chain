#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

GOOD_LOG="$TMP_DIR/good.log"
BAD_LOG="$TMP_DIR/bad.log"
TREASURY_BAD_LOG="$TMP_DIR/treasury-bad.log"

cat >"$GOOD_LOG" <<'EOF'
[event] event_type=challenge task_id=2001 ts_unix_ms=1771840930955 tx_hash=0xaaa treasury_delta=0 challenger_delta=-10 bond_disposition=posted
[event] event_type=resolve task_id=2001 ts_unix_ms=1771840931955 tx_hash=0xaab treasury_delta=0 challenger_delta=10 bond_disposition=refunded
[event] event_type=challenge task_id=2002 ts_unix_ms=1771840932955 tx_hash=0xaac treasury_delta=0 challenger_delta=-8 bond_disposition=posted
[event] event_type=resolve task_id=2002 ts_unix_ms=1771840933955 tx_hash=0xaad treasury_delta=0 challenger_delta=0 bond_disposition=forfeited
EOF

cat >"$BAD_LOG" <<'EOF'
[event] event_type=challenge task_id=3001 ts_unix_ms=1771840930955 tx_hash=0xbaa treasury_delta=0 challenger_delta=-10 bond_disposition=posted
[event] event_type=resolve task_id=3001 ts_unix_ms=1771840931955 tx_hash=0xbab treasury_delta=0 challenger_delta=6 bond_disposition=refunded
EOF

cat >"$TREASURY_BAD_LOG" <<'EOF'
[event] event_type=challenge task_id=4001 ts_unix_ms=1771840930955 tx_hash=0xcaa treasury_delta=5 challenger_delta=-10 bond_disposition=posted
[event] event_type=resolve task_id=4001 ts_unix_ms=1771840931955 tx_hash=0xcab treasury_delta=-5 challenger_delta=10 bond_disposition=refunded
EOF

OUT_GOOD="$TMP_DIR/out-good"
OUT_BAD="$TMP_DIR/out-bad"
OUT_TREASURY_BAD="$TMP_DIR/out-treasury-bad"

SOURCE_LOG="$GOOD_LOG" OUT_DIR="$OUT_GOOD" "$ROOT/scripts/v2/pr5_treasury_reconcile_report.sh" >/dev/null
if ! grep -q '^status=PASS$' "$OUT_GOOD/summary.txt"; then
  echo "[TEST][FAIL] expected PASS for conservation-consistent log"
  cat "$OUT_GOOD/summary.txt"
  exit 1
fi
if ! grep -q '^conservation.gap=0$' "$OUT_GOOD/summary.txt"; then
  echo "[TEST][FAIL] expected conservation.gap=0 for good log"
  cat "$OUT_GOOD/summary.txt"
  exit 1
fi

if SOURCE_LOG="$BAD_LOG" OUT_DIR="$OUT_BAD" "$ROOT/scripts/v2/pr5_treasury_reconcile_report.sh" >/dev/null; then
  echo "[TEST][FAIL] expected non-zero exit when reconcile status=FAIL"
  cat "$OUT_BAD/summary.txt"
  exit 1
fi
if ! grep -q '^status=FAIL$' "$OUT_BAD/summary.txt"; then
  echo "[TEST][FAIL] expected FAIL for conservation-drift log"
  cat "$OUT_BAD/summary.txt"
  exit 1
fi
if ! grep -q '^conservation.detail_count=' "$OUT_BAD/summary.txt"; then
  echo "[TEST][FAIL] expected conservation detail diagnostics"
  cat "$OUT_BAD/summary.txt"
  exit 1
fi

if SOURCE_LOG="$TREASURY_BAD_LOG" OUT_DIR="$OUT_TREASURY_BAD" "$ROOT/scripts/v2/pr5_treasury_reconcile_report.sh" >/dev/null; then
  echo "[TEST][FAIL] expected non-zero exit for treasury_delta anomaly"
  cat "$OUT_TREASURY_BAD/summary.txt"
  exit 1
fi
if ! grep -q '^status=FAIL$' "$OUT_TREASURY_BAD/summary.txt"; then
  echo "[TEST][FAIL] expected FAIL for treasury_delta anomaly"
  cat "$OUT_TREASURY_BAD/summary.txt"
  exit 1
fi
if ! grep -q 'nonzero treasury_delta' "$OUT_TREASURY_BAD/summary.txt"; then
  echo "[TEST][FAIL] expected treasury_delta anomaly detail"
  cat "$OUT_TREASURY_BAD/summary.txt"
  exit 1
fi

echo "[TEST][PASS] pr5 conservation + treasury anomaly regression covered"
