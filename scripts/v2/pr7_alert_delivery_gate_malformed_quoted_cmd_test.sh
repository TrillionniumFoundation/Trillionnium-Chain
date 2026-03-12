#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-malformed-cmd.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

OUT="$TMP/out.log"
set +e
PR7_DELIVERY_CMD="python3 '" \
  "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$OUT" 2>&1
rc=$?
set -e

if [[ "$rc" -ne 2 ]]; then
  echo "[FAIL] expected rc=2 for malformed quoted PR7_DELIVERY_CMD, got rc=$rc" >&2
  cat "$OUT" >&2 || true
  exit 1
fi

if ! grep -q "invalid PR7_DELIVERY_CMD" "$OUT"; then
  echo "[FAIL] expected malformed command parse error in output" >&2
  cat "$OUT" >&2 || true
  exit 1
fi

echo "[OK] pr7 gate rejects malformed quoted PR7_DELIVERY_CMD before running delivery"