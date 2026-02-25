#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

OUT_DIR="$TMP_DIR/out"
SOURCE_LOG="$TMP_DIR/not-found.log"

SOURCE_LOG="$SOURCE_LOG" OUT_DIR="$OUT_DIR" \
  "$ROOT_DIR/scripts/v2/pr5_treasury_reconcile_report.sh" >/dev/null 2>&1

if ! grep -q '^status=SKIP$' "$OUT_DIR/summary.txt"; then
  echo "expected summary status=SKIP" >&2
  cat "$OUT_DIR/summary.txt" >&2 || true
  exit 1
fi

if ! grep -q '^reason=no_event_log_found$' "$OUT_DIR/summary.txt"; then
  echo "expected reason=no_event_log_found" >&2
  cat "$OUT_DIR/summary.txt" >&2 || true
  exit 1
fi

echo "[PASS] pr5_treasury_reconcile_skip_when_missing_log_test"
