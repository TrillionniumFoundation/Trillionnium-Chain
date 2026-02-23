#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP_LOG="$(mktemp /tmp/trnm-fake-wrapper-block.XXXXXX.log)"
trap 'rm -f "$TMP_LOG"' EXIT

echo "[TEST] worker_real_cli_fake_wrapper_block: fake wrapper must fail strict gate"
set +e
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_wrapper.sh \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh >"$TMP_LOG" 2>&1
rc=$?
set -e

if [[ "$rc" -eq 0 ]]; then
  echo "[FAIL] expected strict real-cli gate to reject fake wrapper" >&2
  sed -n '1,120p' "$TMP_LOG" >&2 || true
  exit 1
fi

if ! grep -Eq "\[FAIL\] real tx cli required but not ready|commit-result output missing valid tx_hash|tx query failed" "$TMP_LOG"; then
  echo "[FAIL] strict gate failed but missing expected readiness rejection reason" >&2
  sed -n '1,120p' "$TMP_LOG" >&2 || true
  exit 1
fi

echo "[OK] worker_real_cli_fake_wrapper_block passed (rc=$rc)"
