#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/web4_release_aggregate_gate.sh"

if [[ ! -x "$GATE" ]]; then
  echo "[FAIL] aggregate gate must exist and be executable: $GATE" >&2
  exit 1
fi

BAD_LOG="$(mktemp -t web4-release-bad-stamp.XXXXXX.log)"
GOOD_LOG="$(mktemp -t web4-release-good-stamp.XXXXXX.log)"
trap 'rm -f "$BAD_LOG" "$GOOD_LOG"' EXIT

if WEB4_RELEASE_RUN_STAMP="not-a-stamp" "$GATE" >"$BAD_LOG" 2>&1; then
  echo "[FAIL] aggregate gate should fail on invalid WEB4_RELEASE_RUN_STAMP" >&2
  exit 1
fi

if ! grep -Fq "WEB4_RELEASE_RUN_STAMP must match YYYYMMDD-HHMMSS" "$BAD_LOG"; then
  echo "[FAIL] expected stamp format validation error" >&2
  cat "$BAD_LOG" >&2 || true
  exit 1
fi

STAMP="20260308-060000"
if WEB4_RELEASE_RUN_STAMP="$STAMP" \
   WEB4_RELEASE_REQUIRED_GATES="scripts/v2/definitely_missing_gate.sh" \
   "$GATE" >"$GOOD_LOG" 2>&1; then
  echo "[FAIL] expected aggregate gate negative probe to fail on missing gate" >&2
  exit 1
fi

if ! grep -Fq "run/web4-release-gate/$STAMP" "$GOOD_LOG"; then
  echo "[FAIL] expected deterministic run_dir suffix from WEB4_RELEASE_RUN_STAMP" >&2
  cat "$GOOD_LOG" >&2 || true
  exit 1
fi

echo "[PASS] web4_release_aggregate_gate_run_stamp_validation_test"
