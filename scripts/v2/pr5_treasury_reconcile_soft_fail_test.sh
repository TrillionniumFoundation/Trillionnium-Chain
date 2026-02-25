#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG_FILE="$TMP_DIR/event.log"
cat >"$LOG_FILE" <<'EOF'
[event] event_type=challenge task_id=t1 tx_hash=0xabc ts_unix_ms=1700000000000 treasury_delta=1 challenger_delta=-10 bond_disposition=posted
EOF

OUT_DIR="$TMP_DIR/out"
if ! PR5_RECONCILE_SOFT_FAIL=1 SOURCE_LOG="$LOG_FILE" OUT_DIR="$OUT_DIR" \
  "$ROOT_DIR/scripts/v2/pr5_treasury_reconcile_report.sh" >/dev/null 2>&1; then
  echo "expected soft-fail mode to return success" >&2
  exit 1
fi

if ! grep -q '^status=FAIL$' "$OUT_DIR/summary.txt"; then
  echo "expected summary status=FAIL" >&2
  cat "$OUT_DIR/summary.txt" >&2 || true
  exit 1
fi

echo "[PASS] pr5_treasury_reconcile_soft_fail_test"
